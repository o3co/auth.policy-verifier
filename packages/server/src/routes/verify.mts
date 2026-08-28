// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type AttributePipeline,
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
	type VerifierPayload,
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
 * Validates one entry of a decision request. Returns the entry or the reason it
 * is unusable, phrased with `label` so a batch can name the offending index.
 *
 * The resource string is parsed here rather than at decision time: a string the
 * parser refuses is a malformed request, not a server fault, and it belongs
 * with the other body validation so a batch names the offending index and no
 * entry is decided before the whole batch is known to be usable.
 */
function parseDecisionRequest(
	raw: unknown,
	label: string,
	resourceParser: ResourceParser,
): ParsedDecisionRequest {
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
		return { ok: false, error: `${label} must be an object` };
	}
	const { resource, action, context } = raw as Record<string, unknown>;
	if (typeof resource !== "string" || resource === "") {
		return { ok: false, error: `${label}.resource must be a non-empty string` };
	}
	if (typeof action !== "string" || action === "") {
		return { ok: false, error: `${label}.action must be a non-empty string` };
	}
	// `typeof [] === "object"`, so arrays need excluding explicitly — an array
	// reaching `CollectorContext.requestContext` is a shape no collector expects.
	if (
		context !== undefined &&
		(typeof context !== "object" || context === null || Array.isArray(context))
	) {
		return { ok: false, error: `${label}.context must be an object` };
	}

	let parsedResource: Resource;
	try {
		parsedResource = resourceParser.parse(resource);
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
			request: { resource, action, context: context as Record<string, unknown> | undefined },
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
 * server fault — 401 for authentication failures, and 500 for anything
 * unexpected.
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
	const logger = config.logger ?? consoleLogger;
	// Constructing the authenticator runs assertVerifyRouterJwtConfig, so an
	// invalid hand-built jwt config still fails here, at router construction.
	const authenticator = createTokenAuthenticator(config.jwt, logger);

	/** Runs the pipelines and the evaluator for one already-validated entry. */
	async function decide(
		req: express.Request,
		payload: VerifierPayload,
		{ request: entry, resource }: ValidatedDecisionRequest,
	): Promise<DecisionResponse> {
		const requestId = req.get("x-request-id");
		const headers = requestId ? { "x-request-id": requestId } : undefined;
		// `payload` survived signature verification and `headers` were read off the
		// transport; `entry.context` is whatever the caller put in the body, so it
		// crosses into the collector layer marked as such. A collector has to
		// unwrap it, which is where its author decides what a caller may choose —
		// see `UntrustedRequestContext` in core.
		const context = {
			payload,
			resource,
			action: entry.action,
			headers,
			requestContext: entry.context ? markUntrustedRequestContext(entry.context) : undefined,
		};

		// Timed from here so the measurement is the decision itself — the two
		// pipelines plus evaluation — and not the HTTP round trip. One batch
		// request is many decisions, and it is the per-decision cost that a
		// collector reaching out to a store makes worse.
		const startedAt = performance.now();
		const [attrs, rules] = await Promise.all([
			config.attributePipeline.collect(context),
			config.rulePipeline.collect(context),
		]);
		const decision = evaluate(attrs, rules, config.evaluateOptions);
		const durationMs = performance.now() - startedAt;

		// Derived once and spent twice — on the audit line below and on the
		// response returned at the end (#158). An empty `sub` is absent from both,
		// and the only way the two dispositions of one value cannot drift apart
		// again is for there to be one value.
		const subject = typeof payload.sub === "string" ? present(payload.sub) : undefined;

		// #111: one structured line per decision, and the counters beside it. Both
		// are emitted here rather than at each route so a decision is reported
		// exactly once whether it came through `/verify` or one entry of a batch.
		logger.info(
			decisionEvent({
				decision,
				subject,
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

		return toResponse(subject, entry, decision);
	}

	const router = express.Router();
	router.use(express.json());

	router.post("/verify", async (req: express.Request, res: express.Response) => {
		try {
			const auth = await authenticator.authenticate(req.get("authorization"));
			if (!auth.ok) {
				res.status(401).json(errorBody(auth.code, auth.message));
				return;
			}

			const parsed = parseDecisionRequest(req.body, "body", config.resourceParser);
			if (!parsed.ok) {
				res.status(400).json(errorBody("invalid_request", parsed.error));
				return;
			}

			const decision = await decide(req, auth.payload, parsed.entry);
			res.status(decision.decision === "deny" ? 403 : 200).json(decision);
		} catch (cause) {
			logger.error({ err: cause, endpoint: "/verify" }, "verify_internal_error");
			res.status(500).json(errorBody("internal_error", "Internal server error"));
		}
	});

	router.post("/verify/batch", async (req: express.Request, res: express.Response) => {
		try {
			const auth = await authenticator.authenticate(req.get("authorization"));
			if (!auth.ok) {
				res.status(401).json(errorBody(auth.code, auth.message));
				return;
			}

			const raw = (req.body as { decisions?: unknown } | undefined)?.decisions;
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
				const parsed = parseDecisionRequest(item, `decisions[${index}]`, config.resourceParser);
				if (!parsed.ok) {
					res.status(400).json(errorBody("invalid_request", parsed.error));
					return;
				}
				entries.push(parsed.entry);
			}

			const decisions = await Promise.all(entries.map((entry) => decide(req, auth.payload, entry)));
			res.status(200).json({ decisions });
		} catch (cause) {
			logger.error({ err: cause, endpoint: "/verify/batch" }, "verify_internal_error");
			res.status(500).json(errorBody("internal_error", "Internal server error"));
		}
	});

	return router;
}

/**
 * Projects an engine `Decision` onto the wire contract, naming what it was about.
 *
 * Takes the already-derived `subject` rather than the payload: the audit line
 * and this response must agree about whether the decision had one, and reading
 * `payload.sub` a second time here is what let them disagree (#158).
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
