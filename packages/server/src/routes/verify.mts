// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	AttributeConflictError,
	type AttributePipeline,
	CollectorTimeoutError,
	consoleLogger,
	type Decision,
	type DecisionReason,
	type EvaluateOptions,
	type EventLogger,
	evaluate,
	markUntrustedRequestContext,
	type Resource,
	ResourceParseError,
	type ResourceParser,
	type RulePipeline,
	type SubjectAttributes,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { NUMERIC_BOUNDS, resolveBound } from "../config/bounds.mjs";
import {
	createTokenAuthenticator,
	type VerifyRouterJwtConfig,
} from "../jwt/tokenAuthenticator.mjs";
import { DECISION_EVENT, decisionEvent, present } from "../observability/decisionEvent.mjs";
import type { DecisionMetrics } from "../observability/metrics.mjs";

/** Config for `createVerifyRouter`. The `jwt.key` type is library-specific and is narrowed at call-time. */
export interface VerifyRouterConfig {
	jwt: VerifyRouterJwtConfig;
	resourceParser: ResourceParser;
	attributePipeline: AttributePipeline;
	rulePipeline: RulePipeline;
	/** Evaluator semantics overrides; omitted means engine defaults (deny on an empty rule set). */
	evaluateOptions?: EvaluateOptions;
	/**
	 * Most entries `POST /verify/batch` will decide in one request. Defaults to
	 * 50, and is held to the same bound `AppConfigSchema` holds
	 * `verify.maxBatchSize` to (#157) — a positive integer.
	 *
	 * The string form is admitted for the reason `JwksFetchConfig` admits it:
	 * this is also the boundary a hand-built config reaches, and a caller
	 * assembling one from `process.env` supplies strings.
	 */
	maxBatchSize?: number | string;
	/**
	 * How many of a batch's entries are decided at once (#183). Defaults to 8
	 * (`DEFAULT_BATCH_CONCURRENCY`), and admits the string form for the reason
	 * `maxBatchSize` does. The collector concurrency cap is per decision, so
	 * this is the other factor in what one `POST /verify/batch` may hold in
	 * flight — see the lane loop in the batch route.
	 */
	batchConcurrency?: number | string;
	/**
	 * Ceiling on the JSON body, in bytes — the `limit` handed to
	 * `express.json()`. Defaults to 64 KiB (`DEFAULT_MAX_BODY_BYTES`), below
	 * Express's unstated 100 KB default, and is the outer envelope: it is what
	 * binds first on a large batch, since the per-field limits below bound one
	 * entry rather than N of them.
	 *
	 * This and the four limits after it are held to the same bounds
	 * `AppConfigSchema` holds `verify.*` to (#118, #157), and admit the string
	 * form for the same reason `maxBatchSize` does.
	 */
	maxBodyBytes?: number | string;
	/** Ceiling on the `resource` string, in characters. Defaults to 512. */
	maxResourceLength?: number | string;
	/** Ceiling on the `action` string, in characters. Defaults to 64. */
	maxActionLength?: number | string;
	/**
	 * Ceiling on the size of `context`, counted as every property and every
	 * array element in the whole tree, at every depth. Defaults to 64, which
	 * also bounds the depth — each level costs at least one entry.
	 */
	maxContextEntries?: number | string;
	/**
	 * Ceiling on every string inside `context`, property names included, in
	 * characters. Defaults to 1024.
	 */
	maxContextValueLength?: number | string;
	/**
	 * Sink for the router's failure events (`jwt_token_rejected`,
	 * `jwt_verification_unavailable`, `verify_internal_error`) and for the
	 * per-decision `decision` audit line (#111). Defaults to the console-backed
	 * logger so neither is ever silent in a deployment that wires nothing.
	 *
	 * The decision line is emitted at `info`, so `logging.level` is the switch
	 * that turns the stream off — one knob, no separate flag to forget.
	 */
	logger?: EventLogger;
	/**
	 * Optional counter seam for decisions (#111). Omitted means decisions are
	 * logged but not counted; `createApp` wires the Prometheus implementation.
	 */
	metrics?: DecisionMetrics;
	/**
	 * Whether the raw credential reaches collectors as
	 * `CollectorContext.credential` (#175). Defaults to `"never"`: collectors
	 * get verified claims only, because the credential is replayable and a
	 * collector that logs its context would leak a live token. `"expose"` is
	 * for the deployment whose project-side collector calls a downstream API
	 * *as the subject* (token forwarding/exchange) — a decision that belongs
	 * in config, where it is greppable, not in ambient behavior.
	 *
	 * An enum rather than a boolean on purpose: `${?ENV}` substitution hands
	 * schemas strings, and a string survives an enum unharmed where a bare
	 * boolean invites the coercion-path drift o3co/auth.provider#288 documents.
	 */
	credentialToCollectors?: "never" | "expose";
}

/**
 * One decision the caller is asking for. The subject is deliberately absent:
 * it comes from the verified token, never from the body — accepting one here
 * would let any token holder ask for a decision about somebody else.
 */
export interface DecisionRequest {
	resource: string;
	action: string;
	context?: Record<string, unknown>;
}

/**
 * What the endpoint decided, and for whom.
 *
 * The four inputs an engine needs — subject, resource, action, context — are
 * named explicitly, and the outcome carries a structured `reason` rather than a
 * bare allow/deny. That is what lets a heavy-class engine (OPA's
 * `input document → decision`, OpenFGA's `check(user, relation, object)`, Cedar)
 * sit behind this same contract: the request carries enough for each of them to
 * form its own query, and the response has somewhere to put what decided.
 */
export interface DecisionResponse {
	/**
	 * JWT `sub` of the token presented. Absent when the token carries none — and
	 * an empty `sub` counts as none, the disposition the audit line takes for the
	 * same value (#158). `subject: ""` would name a subject that does not exist,
	 * and every token without one would name the same one.
	 */
	subject?: string;
	resource: string;
	action: string;
	decision: "allow" | "deny";
	/** Present on deny — the first failing group's representative rule. */
	code?: string;
	/** Present on deny — the first failing group's representative rule. */
	message?: string;
	reason: DecisionReason;
}

/** Error envelope shared by every non-decision response. */
interface ErrorBody {
	decision: "deny";
	code: string;
	message: string;
}

const errorBody = (code: string, message: string): ErrorBody => ({
	decision: "deny",
	code,
	message,
});

/**
 * The deny a collector fan-out that ran out of time is answered with (#115).
 *
 * A deny, and specifically not a 5xx. The caller asked whether this request is
 * authorized; what the verifier can stand behind when a collector stalled is
 * "not established", and the safe rendering of that is a refusal. A 500 invites
 * the enforcement layer to retry the same stalled dependency, or to conclude the
 * PDP is down and apply a fallback of its own — and a fallback nobody in this
 * repo wrote is precisely the fail-open being closed here.
 *
 * The message is fixed and says nothing about which collector or which bound:
 * that reaches the caller, and the collector set is deployment topology. The
 * detail is in the `collector_timeout` log line instead, where an operator can
 * act on it.
 */
const COLLECTOR_TIMEOUT_CODE = "collector_timeout";
const COLLECTOR_TIMEOUT_MESSAGE = "Authorization could not be decided in time";
const ATTRIBUTE_CONFLICT_CODE = "attribute_conflict";
const ATTRIBUTE_CONFLICT_MESSAGE = "Authorization inputs conflicted";

/** One validated entry: the request as sent, plus its resource already parsed. */
interface ValidatedDecisionRequest {
	request: DecisionRequest;
	resource: Resource;
}

/** Outcome of validating one decision request: either the parsed entry or the reason it is unusable. */
type ParsedDecisionRequest =
	| { ok: true; entry: ValidatedDecisionRequest }
	| { ok: false; error: string };

/**
 * The bounds one decision request is held to (#118), resolved once at router
 * construction. Body bytes are not here: that limit is spent by `express.json()`
 * before a body is ever an object.
 */
interface RequestLimits {
	maxResourceLength: number;
	maxActionLength: number;
	maxContextEntries: number;
	maxContextValueLength: number;
}

/** Properties a decision request may carry. Anything else is refused (#118). */
const DECISION_REQUEST_KEYS = new Set(["resource", "action", "context"]);

/** How many unknown property names a refusal names before it stops listing them. */
const MAX_RENDERED_KEYS = 3;

/**
 * Longest a rendered property name may be, the ellipsis that replaces the tail
 * included — so a truncated name is exactly this long, never one character over.
 */
const MAX_RENDERED_KEY_LENGTH = 32;

/**
 * Renders unknown property names for an error message.
 *
 * The names are the caller's own text, so what reaches the response is bounded
 * here rather than by whatever they sent: at most {@link MAX_RENDERED_KEYS}
 * names, each at most {@link MAX_RENDERED_KEY_LENGTH} characters *including*
 * the ellipsis that stands in for the tail. The truncation is stated that way,
 * and spelled `MAX_RENDERED_KEY_LENGTH - 1`, because a bound whose own error
 * path runs one character past what it documents is the shape this whole change
 * is against.
 *
 * Quoting happens after: each name goes through `JSON.stringify`, so one
 * carrying quotes or control characters cannot reshape the message. That adds
 * the two quotes and any escape expansion on top of the length above — the
 * bound is on the name, not on its JSON rendering, which is the only honest way
 * to state it when a single character can escape to six.
 */
function describeUnknownKeys(keys: readonly string[]): string {
	const shown = keys
		.slice(0, MAX_RENDERED_KEYS)
		.map((key) =>
			JSON.stringify(
				key.length > MAX_RENDERED_KEY_LENGTH
					? `${key.slice(0, MAX_RENDERED_KEY_LENGTH - 1)}…`
					: key,
			),
		);
	return keys.length > shown.length ? `${shown.join(", ")}, …` : shown.join(", ");
}

/**
 * Rejects a `resource` / `action` that is absent, empty, over its length bound,
 * or carries whitespace. Returns the string once it is known to be one, so the
 * caller reads a `string` rather than re-narrowing the `unknown` it passed in.
 *
 * **Whitespace is refused, not trimmed**, which is the doctrine
 * `DotNotationResourceParser` already applies to `resource` (#117), applied here
 * so it also covers `action` and a deployment that registered its own parser.
 * Both strings are structural identifiers rather than free text: they are echoed
 * back in the decision, and `ResourceActionScopeRuleCollector` concatenates them
 * into the `{action}:{resourceType}` scope an issuer has to have granted — and
 * RFC 6749 §3.3 makes space the delimiter between scope values, so a value
 * carrying whitespace names something no issuer could grant. Trimming would
 * instead make `"read "` and `"read"` one action here while a collector reading
 * the raw string still saw two.
 *
 * The value is never echoed: the message names the field. These strings are
 * chosen by the caller and end up in logs and pasted bug reports.
 */
function checkIdentifier(
	value: unknown,
	field: string,
	label: string,
	maxLength: number,
): { ok: true; value: string } | { ok: false; error: string } {
	if (typeof value !== "string" || value === "") {
		return { ok: false, error: `${label}.${field} must be a non-empty string` };
	}
	if (value.length > maxLength) {
		return {
			ok: false,
			error: `${label}.${field} must not be longer than ${maxLength} characters`,
		};
	}
	if (/\s/.test(value)) {
		return { ok: false, error: `${label}.${field} must not contain whitespace` };
	}
	return { ok: true, value };
}

/**
 * Holds the caller's `context` to its size bounds, or explains which one it
 * broke.
 *
 * Nesting is counted rather than forbidden: `RequestContextAttributeCollector`
 * reads dot paths such as `tenant.id`, so a flat-only rule would break a
 * documented feature. Every property and every array element counts, at every
 * depth, which is also what keeps this walk finite — a context inside
 * `maxContextEntries` can be at most that deep, so no separate depth bound is
 * needed and the traversal is iterative regardless.
 *
 * Neither message echoes a key or a value. The whole object is caller-supplied,
 * which is exactly why it is bounded, and a message that quoted part of it would
 * hand the size back to the caller.
 */
function checkContext(
	context: Record<string, unknown>,
	label: string,
	limits: RequestLimits,
): string | undefined {
	const tooMany =
		`${label}.context must not carry more than ${limits.maxContextEntries} entries ` +
		"(every property and array element counts, at every depth)";
	const tooLong =
		`${label}.context must not carry a string longer than ${limits.maxContextValueLength} ` +
		"characters (property names included)";

	let entries = 0;
	const pending: object[] = [context];
	while (pending.length > 0) {
		// Non-null by construction: only containers are pushed.
		const node = pending.pop() as object;
		const isArray = Array.isArray(node);
		for (const [key, value] of Object.entries(node)) {
			entries += 1;
			if (entries > limits.maxContextEntries) return tooMany;
			// An array's `Object.entries` keys are its indices, which the caller
			// did not write and which no bound applies to.
			if (!isArray && key.length > limits.maxContextValueLength) return tooLong;
			if (typeof value === "string" && value.length > limits.maxContextValueLength) return tooLong;
			if (typeof value === "object" && value !== null) pending.push(value);
		}
	}
	return undefined;
}

/**
 * Validates one entry of a decision request. Returns the entry or the reason it
 * is unusable, phrased with `label` so a batch can name the offending index.
 *
 * The resource string is parsed here rather than at decision time: a string the
 * parser refuses is a malformed request, not a server fault, and it belongs
 * with the other body validation so a batch names the offending index and no
 * entry is decided before the whole batch is known to be usable.
 *
 * Unknown properties are refused rather than ignored (#118). A caller sending
 * `subject` was being told nothing while believing it had been honoured — and
 * the subject comes from the verified token, never from the body. The same
 * reasoning covers a misspelled `contxt`, which used to be dropped in silence.
 */
function parseDecisionRequest(
	raw: unknown,
	label: string,
	resourceParser: ResourceParser,
	limits: RequestLimits,
): ParsedDecisionRequest {
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
		return { ok: false, error: `${label} must be an object` };
	}
	const unknownKeys = Object.keys(raw).filter((key) => !DECISION_REQUEST_KEYS.has(key));
	if (unknownKeys.length > 0) {
		return {
			ok: false,
			error:
				`${label} has unknown properties: ${describeUnknownKeys(unknownKeys)} ` +
				"(only resource, action and context are accepted)",
		};
	}
	const { resource, action, context } = raw as Record<string, unknown>;
	const checkedResource = checkIdentifier(resource, "resource", label, limits.maxResourceLength);
	if (!checkedResource.ok) {
		return checkedResource;
	}
	const checkedAction = checkIdentifier(action, "action", label, limits.maxActionLength);
	if (!checkedAction.ok) {
		return checkedAction;
	}
	// `typeof [] === "object"`, so arrays need excluding explicitly — an array
	// reaching `CollectorContext.requestContext` is a shape no collector expects.
	if (
		context !== undefined &&
		(typeof context !== "object" || context === null || Array.isArray(context))
	) {
		return { ok: false, error: `${label}.context must be an object` };
	}
	if (context !== undefined) {
		const badContext = checkContext(context as Record<string, unknown>, label, limits);
		if (badContext !== undefined) {
			return { ok: false, error: badContext };
		}
	}

	let parsedResource: Resource;
	try {
		parsedResource = resourceParser.parse(checkedResource.value);
	} catch (cause) {
		// Only a ResourceParseError means "the caller's string is malformed".
		// Anything else is a fault in the parser and must keep surfacing as a 500.
		if (!(cause instanceof ResourceParseError)) throw cause;
		return {
			ok: false,
			error: `${label}.resource is not a valid resource string "${cause.raw}": ${cause.detail}`,
		};
	}

	return {
		ok: true,
		entry: {
			request: {
				resource: checkedResource.value,
				action: checkedAction.value,
				context: context as Record<string, unknown> | undefined,
			},
			resource: parsedResource,
		},
	};
}

/**
 * Builds the Express router serving the decision endpoints.
 *
 * `POST /verify` — `Authorization: Bearer <jwt>`, body
 * `{ resource, action, context? }`; answers a {@link DecisionResponse} with 200
 * on allow and 403 on deny.
 *
 * `POST /verify/batch` — body `{ decisions: [{ resource, action, context? }, …] }`;
 * answers `200 { decisions: DecisionResponse[] }` in request order. The status
 * reports whether the batch was decided, not what it decided, so a batch of
 * denials is still 200 — the caller reads each entry. Filtering a list of N
 * resources is one round trip rather than N.
 *
 * Both answer 400 for a malformed body — including a `resource` the configured
 * `ResourceParser` refuses, which is the caller's syntax error rather than a
 * server fault — 401 for authentication failures, 413 for a body over
 * `maxBodyBytes`, 415 for a content type the parser cannot read, and 500 for
 * anything unexpected. Every one of those answers is the deny envelope
 * `{ decision: "deny", code, message }`, the body-parser failures included
 * (#118): a caller that parses only decision JSON must never be handed
 * Express's HTML error page.
 *
 * **The body is validated before the token is verified** (#118), which is why a
 * malformed unauthenticated request is answered 400 rather than 401. It is the
 * order the costs argue for: the body checks are bounded by the limits above,
 * while verifying a token is the half that can reach the network — an
 * attacker-chosen `kid` sends the JWKS path to the provider, and an HS256
 * rotation tries every configured secret — so doing it first let an
 * unauthenticated caller spend it on a body that was never usable. What it
 * costs is that an anonymous caller now learns whether a body was well-formed,
 * the resource grammar included; `http.callerAuth` (#108) is the gate for
 * deployments that must not disclose even that, and it stays ahead of this
 * router and of `express.json()`.
 *
 * Every decision — one per `/verify` call, one per entry of a batch — emits a
 * `decision` event at info and, when `metrics` is wired, increments the
 * decision counters (#111). Requests that never reached the evaluator (401,
 * 400) emit neither, so the log stream and the metric agree on what a decision
 * is. See `observability/decisionEvent.mts` for what the line does and does not
 * carry.
 */
export function createVerifyRouter(config: VerifyRouterConfig): express.Router {
	// Resolved rather than defaulted with `??` (#157): this is the boundary a
	// hand-built config reaches, so it must refuse what `AppConfigSchema` refuses
	// and in the same words. `??` read `null` as "unset" — a 50-entry cap where
	// the schema refused to boot — and let a `0` through as a cap that rejects
	// every batch there is.
	const maxBatchSize = resolveBound(config.maxBatchSize, NUMERIC_BOUNDS.maxBatchSize, "verify");
	const batchConcurrency = resolveBound(
		config.batchConcurrency,
		NUMERIC_BOUNDS.batchConcurrency,
		"verify",
	);
	// The request limits (#118), read the same way and at the same boundary.
	const maxBodyBytes = resolveBound(config.maxBodyBytes, NUMERIC_BOUNDS.maxBodyBytes, "verify");
	const limits: RequestLimits = {
		maxResourceLength: resolveBound(
			config.maxResourceLength,
			NUMERIC_BOUNDS.maxResourceLength,
			"verify",
		),
		maxActionLength: resolveBound(config.maxActionLength, NUMERIC_BOUNDS.maxActionLength, "verify"),
		maxContextEntries: resolveBound(
			config.maxContextEntries,
			NUMERIC_BOUNDS.maxContextEntries,
			"verify",
		),
		maxContextValueLength: resolveBound(
			config.maxContextValueLength,
			NUMERIC_BOUNDS.maxContextValueLength,
			"verify",
		),
	};
	const logger = config.logger ?? consoleLogger;
	// Constructing the authenticator runs assertVerifyRouterJwtConfig, so an
	// invalid hand-built jwt config still fails here, at router construction.
	const authenticator = createTokenAuthenticator(config.jwt, logger);
	// #175: resolved once — the per-request cost is a spread, not a branch tree.
	const exposeCredential = config.credentialToCollectors === "expose";

	/** Runs the pipelines and the evaluator for one already-validated entry. */
	async function decide(
		req: express.Request,
		auth: { subject: SubjectAttributes; credential: string },
		{ request: entry, resource }: ValidatedDecisionRequest,
	): Promise<DecisionResponse> {
		const subject = auth.subject;
		const requestId = req.get("x-request-id");
		const headers = requestId ? { "x-request-id": requestId } : undefined;
		// `subject` was populated from a credential the authenticator verified and
		// `headers` were read off the transport; `entry.context` is whatever the
		// caller put in the body, so it crosses into the collector layer marked as
		// such. A collector has to unwrap it, which is where its author decides
		// what a caller may choose — see `UntrustedRequestContext` in core.
		const context = {
			subject,
			resource,
			action: entry.action,
			headers,
			requestContext: entry.context ? markUntrustedRequestContext(entry.context) : undefined,
			// #175: absent unless the composition said "expose" — see the
			// config field's doc. Spread-conditional so the default context
			// carries no `credential` key at all, not an undefined one.
			...(exposeCredential ? { credential: auth.credential } : {}),
		};

		// Timed from here so the measurement is the decision itself — the two
		// pipelines plus evaluation — and not the HTTP round trip. One batch
		// request is many decisions, and it is the per-decision cost that a
		// collector reaching out to a store makes worse.
		const startedAt = performance.now();
		let decision: Decision;
		try {
			const [attrs, rules] = await Promise.all([
				config.attributePipeline.collect(context),
				config.rulePipeline.collect(context),
			]);
			decision = evaluate(attrs, rules, config.evaluateOptions);
		} catch (cause) {
			// Two collect failures are denies of their own (#115 timeouts, #174
			// attribute conflicts); anything else is a genuine fault and keeps
			// surfacing as a 500.
			const denial =
				cause instanceof CollectorTimeoutError
					? { code: COLLECTOR_TIMEOUT_CODE, message: COLLECTOR_TIMEOUT_MESSAGE }
					: cause instanceof AttributeConflictError
						? { code: ATTRIBUTE_CONFLICT_CODE, message: ATTRIBUTE_CONFLICT_MESSAGE }
						: null;
			if (denial === null) throw cause;
			// The evaluator is deliberately never reached: it is the one place a
			// short rule list could still be read as a policy, and `onEmptyRuleSet:
			// "allow"` would then turn a timed-out (or conflicted) pipeline into a
			// permit. A deny is built here instead, with an empty `reason` because
			// no rule group was evaluated — which is the honest account of what
			// happened. The conflicted attribute KEY reaches the log line via the
			// error's message; the caller's message names neither key nor values.
			logger.error(
				{ err: cause, resource: entry.resource, action: entry.action, requestId },
				denial.code,
			);
			decision = {
				decision: "deny",
				code: denial.code,
				message: denial.message,
				reason: { groups: [] },
			};
		}
		const durationMs = performance.now() - startedAt;

		// Derived once and spent twice — on the audit line below and on the
		// response returned at the end (#158). An empty `sub` is absent from both,
		// and the only way the two dispositions of one value cannot drift apart
		// again is for there to be one value.
		const subjectId = typeof subject.sub === "string" ? present(subject.sub) : undefined;

		// #111: one structured line per decision, and the counters beside it. Both
		// are emitted here rather than at each route so a decision is reported
		// exactly once whether it came through `/verify` or one entry of a batch.
		logger.info(
			decisionEvent({
				decision,
				subject: subjectId,
				resource: entry.resource,
				action: entry.action,
				requestId,
				durationMs,
			}),
			DECISION_EVENT,
		);
		config.metrics?.observe({
			decision: decision.decision,
			// `resource` and `action` are deliberately not passed: they come from
			// the request body and would be unbounded metric labels. They are on
			// the log line above instead.
			code: decision.decision === "deny" ? decision.code : undefined,
			durationSeconds: durationMs / 1000,
		});

		return toResponse(subjectId, entry, decision);
	}

	const router = express.Router();
	// An explicit limit, not Express's unstated 100 KB default (#118). It is the
	// only one of the five spent here: a body over it never becomes an object,
	// and `bodyParserFailure` below turns the refusal into the deny envelope.
	router.use(express.json({ limit: maxBodyBytes }));

	router.post("/verify", async (req: express.Request, res: express.Response) => {
		try {
			// Body first, token second (#118) — see the ordering paragraph on
			// `createVerifyRouter`. This is what makes a malformed unauthenticated
			// request a 400 rather than a 401.
			const parsed = parseDecisionRequest(req.body, "body", config.resourceParser, limits);
			if (!parsed.ok) {
				res.status(400).json(errorBody("invalid_request", parsed.error));
				return;
			}

			const auth = await authenticator.authenticate(req.get("authorization"));
			if (!auth.ok) {
				res.status(401).json(errorBody(auth.code, auth.message));
				return;
			}

			const decision = await decide(req, auth, parsed.entry);
			res.status(decision.decision === "deny" ? 403 : 200).json(decision);
		} catch (cause) {
			logger.error({ err: cause, endpoint: "/verify" }, "verify_internal_error");
			res.status(500).json(errorBody("internal_error", "Internal server error"));
		}
	});

	router.post("/verify/batch", async (req: express.Request, res: express.Response) => {
		try {
			// The whole body — envelope, cap and every entry — before the token, for
			// the reason `/verify` does it: the batch is the shape that can make an
			// unauthenticated caller's mistake expensive.
			const body: unknown = req.body;
			if (typeof body !== "object" || body === null || Array.isArray(body)) {
				res.status(400).json(errorBody("invalid_request", "body must be an object"));
				return;
			}
			const unknownKeys = Object.keys(body).filter((key) => key !== "decisions");
			if (unknownKeys.length > 0) {
				res
					.status(400)
					.json(
						errorBody(
							"invalid_request",
							`body has unknown properties: ${describeUnknownKeys(unknownKeys)} (only decisions is accepted)`,
						),
					);
				return;
			}
			const raw = (body as { decisions?: unknown }).decisions;
			if (!Array.isArray(raw) || raw.length === 0) {
				res.status(400).json(errorBody("invalid_request", "decisions must be a non-empty array"));
				return;
			}
			if (raw.length > maxBatchSize) {
				res
					.status(400)
					.json(
						errorBody(
							"invalid_request",
							`decisions must contain at most ${maxBatchSize} entries, got ${raw.length}`,
						),
					);
				return;
			}

			// Validate the whole batch before deciding any of it: a caller that sent
			// one malformed entry gets told which, rather than a partial answer.
			const entries: ValidatedDecisionRequest[] = [];
			for (const [index, item] of raw.entries()) {
				const parsed = parseDecisionRequest(
					item,
					`decisions[${index}]`,
					config.resourceParser,
					limits,
				);
				if (!parsed.ok) {
					res.status(400).json(errorBody("invalid_request", parsed.error));
					return;
				}
				entries.push(parsed.entry);
			}

			const auth = await authenticator.authenticate(req.get("authorization"));
			if (!auth.ok) {
				res.status(401).json(errorBody(auth.code, auth.message));
				return;
			}

			// Decided in lanes, batchConcurrency wide, not under a bare
			// `Promise.all` (#183): the collector concurrency cap is per
			// decision, so starting every entry at once multiplied it by the
			// batch size — one request at the default caps could hold
			// 50 × 8 collectors in flight per pipeline against a dependency
			// that had just started to slow down. The same shared-cursor shape
			// as core's runCollectors; each lane writes into the entry's own
			// slot, so the answer order is the request order however the lanes
			// interleave.
			const decisions = new Array<DecisionResponse>(entries.length);
			let next = 0;
			let abandoned = false;
			const lane = async (): Promise<void> => {
				while (!abandoned && next < entries.length) {
					const index = next++;
					decisions[index] = await decide(req, auth, entries[index]);
				}
			};
			try {
				await Promise.all(
					Array.from({ length: Math.min(batchConcurrency, entries.length) }, () => lane()),
				);
			} catch (cause) {
				// A decide that throws is a genuine fault — denials are answered
				// inside it — and the 500 below speaks for the whole batch, so
				// the lanes stop pulling entries nobody will read. What is
				// already in flight settles on its own, exactly as it did under
				// Promise.all.
				abandoned = true;
				throw cause;
			}
			res.status(200).json({ decisions });
		} catch (cause) {
			logger.error({ err: cause, endpoint: "/verify/batch" }, "verify_internal_error");
			res.status(500).json(errorBody("internal_error", "Internal server error"));
		}
	});

	/*
	 * Terminal error handler (#118, and item 6 of #126).
	 *
	 * `express.json()` rejects before either route runs, so its failures never
	 * reached the try/catch above and fell through to Express's default handler
	 * — an HTML page, carrying a stack trace outside production. A client that
	 * parses only decision JSON has no way to read that, and "every non-allow
	 * answer is a deny" stops being something the endpoint actually does.
	 *
	 * It is mounted on the router rather than on the app so that
	 * `createVerifyRouter` is self-contained: a consumer mounting it on their own
	 * Express app gets the envelope without wiring anything, and `createApp`
	 * inherits it. Four arguments, because that is how Express tells an error
	 * handler from a middleware.
	 */
	const denyOnBodyFailure: express.ErrorRequestHandler = (err, req, res, next) => {
		// A failure after the response started is not ours to rewrite; handing it
		// back lets Express close the connection.
		if (res.headersSent) {
			next(err);
			return;
		}
		const failure = bodyParserFailure(err);
		if (failure) {
			res.status(failure.status).json(errorBody(failure.code, failure.message));
			return;
		}
		// `req.path`, not a literal: this handler covers both routes, and anything
		// mounted on the router that never reached one of them.
		logger.error({ err, endpoint: req.path }, "verify_internal_error");
		res.status(500).json(errorBody("internal_error", "Internal server error"));
	};
	router.use(denyOnBodyFailure);

	return router;
}

/**
 * Maps a body-parser failure onto a status and a deny code, or `undefined` when
 * the error is not one.
 *
 * body-parser tags every failure it raises with a stable `type`, which is what
 * is matched here — `err.message` carries a fragment of the caller's body and
 * `err.status` alone would not tell an oversized body from an unreadable
 * charset. None of the messages echo anything the caller sent: a parse failure
 * is reported as a parse failure, not by quoting the bytes that caused it.
 */
function bodyParserFailure(
	err: unknown,
): { status: number; code: string; message: string } | undefined {
	switch ((err as { type?: unknown } | null)?.type) {
		case "entity.too.large":
			return {
				status: 413,
				code: "payload_too_large",
				message: "Request body exceeds the configured limit",
			};
		case "entity.parse.failed":
			return { status: 400, code: "invalid_request", message: "Request body is not valid JSON" };
		case "encoding.unsupported":
		case "charset.unsupported":
			return {
				status: 415,
				code: "unsupported_media_type",
				message: "Request body must be application/json encoded as UTF-8",
			};
		case "request.aborted":
			return {
				status: 400,
				code: "invalid_request",
				message: "Request body was not fully received",
			};
		default:
			return undefined;
	}
}

/**
 * Projects an engine `Decision` onto the wire contract, naming what it was about.
 *
 * Takes the already-derived `subject` id rather than the subject bag: the audit
 * line and this response must agree about whether the decision had one, and
 * reading `subject.sub` a second time here is what let them disagree (#158).
 */
function toResponse(
	subject: string | undefined,
	entry: DecisionRequest,
	decision: Decision,
): DecisionResponse {
	const base = {
		...(subject !== undefined ? { subject } : {}),
		resource: entry.resource,
		action: entry.action,
		reason: decision.reason,
	};
	return decision.decision === "deny"
		? { ...base, decision: "deny", code: decision.code, message: decision.message }
		: { ...base, decision: "allow" };
}
