// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `http` engine: evaluates the policy set out of process by pushing it to a
 * cedar-agent at load and asking the agent per request. Also holds the
 * resolution of its endpoint, token and answer bound, and the rendering of
 * Cedar entity references; the package index registers it.
 */

import type { Logger } from "@o3co/auth.policy-verifier.core";
import type { CedarEntityUid } from "./cedarJson.mjs";
import {
	type AsyncCedarPolicySet,
	type CedarDecision,
	type CedarEngine,
	CedarEngineError,
	type CedarEngineLoadContext,
	type ForeignAnswer,
} from "./engine.mjs";
import type { CedarRequest } from "./mapping.mjs";
import { namePolicies, type PolicySource } from "./policySource.mjs";

/** The name this engine registers under, and the config value that selects it. */
export const CEDAR_HTTP_ENGINE_NAME = "http" as const;

/** Environment variable that overrides the endpoint when config does not set it. */
export const CEDAR_ENDPOINT_ENV = "CEDAR_ENDPOINT";

/** Environment variable carrying the agent's `Authorization` token, when it enforces one. */
export const CEDAR_AUTHENTICATION_ENV = "CEDAR_AUTHENTICATION";

/** How long boot waits for the engine to accept the policy set, retrying while it is unreachable. */
export const CEDAR_LOAD_TIMEOUT_MS = 10_000;

/**
 * The default for `maxAnswerBytes`: the maximum number of bytes the engine
 * reads from one answer from the agent. A longer answer — declared by
 * `content-length` or streamed — is refused, a deny, rather than held in
 * memory for the rule's deadline: a faulty agent, or a proxy in front of it,
 * would otherwise hold that per concurrent call, and a process out of memory
 * takes every route down, not only the ones Cedar gates (#271). An answer's
 * determining-policy and error lists grow with the policy set, so a large set
 * can answer honestly past it; the collector's `maxAnswerBytes` raises it.
 */
export const CEDAR_ANSWER_MAX_BYTES = 1024 * 1024;

const LOAD_RETRY_MS = 500;
const POLICIES_PATH = "/v1/policies";
const IS_AUTHORIZED_PATH = "/v1/is_authorized";

/** Constructor options, for composition and tests; the registered engine uses the defaults. */
export interface CedarHttpEngineOptions {
	/**
	 * The `fetch` to call. Defaults to the global one, looked up per call. It
	 * must honour `init.redirect`: both calls ask for `"manual"` so that a 3xx
	 * fails closed (#270), and a `fetch` that follows redirects anyway undoes that.
	 * It must also reject once `init.signal` aborts, and fail a body still being
	 * read, as the platform's does: the load tells its deadline apart from other
	 * failures by that signal, and a body that stalls ends there (#271).
	 */
	fetch?: typeof fetch;
	/** Where `CEDAR_ENDPOINT` / `CEDAR_AUTHENTICATION` are read. Defaults to `process.env`. */
	env?: Readonly<Record<string, string | undefined>>;
	/** How long `load` keeps retrying an unreachable engine. Defaults to {@link CEDAR_LOAD_TIMEOUT_MS}. */
	loadTimeoutMs?: number;
	/** The pause between those retries. Defaults to 500 ms. */
	retryMs?: number;
}

/** What one authorization call sends: cedar-agent's `AuthorizationCall`, entities inline. */
interface AgentAuthorizationCall {
	principal: string;
	action: string;
	resource: string;
	context: CedarRequest["context"];
	entities: CedarRequest["entities"];
}

/**
 * The out-of-process Cedar engine: a [cedar-agent](https://github.com/permitio/cedar-agent)
 * reached over HTTP, behind the `CedarEngine` port.
 *
 * ## What it does
 *
 * At `load` the policy set is pushed to the agent — `PUT /v1/policies`, one
 * entry per file, under the file's name and the load's mark (`agentPolicyId`,
 * #283) — so the agent holds
 * exactly the verifier's `config/policies` and nothing has to be converted or
 * mounted twice. The agent parses on receipt; a set it refuses fails boot
 * here, with the agent's message and the ids that were sent (the agent does
 * not say which one it choked on). Per request, `POST /v1/is_authorized` carries the
 * same `CedarRequest` the wasm engine evaluates, entities inline, and the
 * agent's `{ decision, diagnostics }` comes back as a {@link CedarDecision}.
 * The loaded set is asynchronous, so the collector builds an `AsyncRule` and
 * every call runs under the server's `verify.ruleTimeoutMs`; the signal that
 * deadline aborts is handed to `fetch`.
 *
 * ## Where the agent is
 *
 * `endpoint` in the collector's config entry, else `CEDAR_ENDPOINT`. Neither
 * is a boot error that names both ways out — this engine is also what a
 * deployment gets when it upgraded without importing the wasm package, and a
 * default address would turn that into ten seconds of "unreachable", or a
 * boot against whatever answered there (v0.10.0 audit; #225 specified the
 * error). The standalone template's compose file sets `CEDAR_ENDPOINT` for
 * its `cedar-engine` profile. A base URL: the two paths above are appended. Plain `http://` is accepted for loopback hosts only; anything
 * routable must be `https://`, the rule `jwksUri` follows, because the wire
 * carries the request's attributes and the agent's answer is an authorization.
 * `authentication` in config, else `CEDAR_AUTHENTICATION`, is sent verbatim as
 * the `Authorization` header — the value the agent was started with. A value
 * `fetch` cannot send — an ASCII control character other than a tab inside
 * it, a character above U+00FF — is refused at load, naming where it came
 * from and not the value: `fetch`'s own refusal can quote it whole, and the
 * load would have called the agent unreachable (#271).
 *
 * ## What it asks of the policy set
 *
 * cedar-agent stores policies one by one, so **each `.cedar` file must hold
 * exactly one policy** (and inline `policies` one policy); a file with two is
 * refused at boot with the agent's message. Each is given the id
 * `namePolicies` makes of its file's name — the id the wasm engine compiles a
 * one-policy file under too — so a corpus laid out one policy per file works
 * under both and names its policies alike (#199); the agent holds it under
 * that id and the load's mark (`agentPolicyId`, #283), by which an answer from
 * a set this verifier did not load is told apart. `PUT /v1/policies` replaces the agent's
 * whole set, so one collector per agent: a second `load` against the same
 * endpoint is refused rather than silently overwriting the first.
 *
 * ## Failure is loud and closed
 *
 * Boot retries a connection refusal for {@link CEDAR_LOAD_TIMEOUT_MS} (a
 * compose sibling may be a few hundred milliseconds behind) and then refuses
 * to start; a load answered with a 3xx fails boot at once. After boot, an
 * agent that is unreachable, answers non-2xx, breaks off its answer or answers
 * something that is not a decision rejects with {@link CedarEngineError}; the
 * collector logs it and denies, never abstains. No redirect is followed
 * (#270): a 3xx is non-2xx, so `endpoint` must be the URL that answers the
 * calls itself.
 *
 * Each failure says what failed (#271). A transport failure names the cause
 * `fetch` keeps on its error — `connect ECONNREFUSED 127.0.0.1:8180`,
 * `getaddrinfo ENOTFOUND …`, a TLS code — rather than "fetch failed" for all
 * of them. An abort rejects with the signal's reason wherever it lands, before
 * the answer or while its body is read. A load whose deadline passes is
 * reported as no answer in time, with how the attempt before failed, never as
 * a reachable agent: a timeout does not show the connection was made. An
 * answer longer than `maxAnswerBytes` in the collector's config entry —
 * {@link CEDAR_ANSWER_MAX_BYTES} when it is absent — is refused, not read.
 */
export function createCedarHttpEngine(options: CedarHttpEngineOptions = {}): CedarEngine {
	const env = options.env ?? process.env;
	const doFetch: typeof fetch = (input, init) => (options.fetch ?? globalThis.fetch)(input, init);
	const loadTimeoutMs = options.loadTimeoutMs ?? CEDAR_LOAD_TIMEOUT_MS;
	const retryMs = options.retryMs ?? LOAD_RETRY_MS;
	/** Endpoints already holding a policy set from this engine — one collector per agent. */
	const loaded = new Map<string, string>();

	return {
		name: CEDAR_HTTP_ENGINE_NAME,
		async: true,

		async load(source: PolicySource, context: CedarEngineLoadContext) {
			const endpoint = resolveEndpoint(context.config.endpoint, env[CEDAR_ENDPOINT_ENV]);
			const headers = requestHeaders(context.config.authentication, env[CEDAR_AUTHENTICATION_ENV]);
			const maxAnswerBytes = resolveMaxAnswerBytes(context.config.maxAnswerBytes);

			const nonBlank = source.files.filter((file) => file.text.trim().length > 0);
			// One policy per file (see the doc comment), so each file is one
			// policy — named before the endpoint is reserved, so a refusal holds nothing.
			// Pushed under this load's mark (#283); the file id is what a decision records.
			const named = namePolicies(nonBlank, (file) => [file.text]);
			const ownIds = new Map(named.map(({ id }) => [agentPolicyId(id, source.revision), id]));
			const ownMark = loadMark(source.revision);
			const policies = named.map(({ id, text }) => ({
				id: agentPolicyId(id, source.revision),
				content: text,
			}));

			const agent = agentKey(endpoint);
			const holder = loaded.get(agent);
			if (holder !== undefined) {
				throw new CedarEngineError(
					`cedar engine at ${endpoint} already holds the policy set from ${holder} — PUT /v1/policies replaces an agent's whole set, so run one CedarPolicyRuleCollector per agent`,
				);
			}
			// Reserved before the first request, not after the last: two collectors
			// loading concurrently must not both pass the check above.
			loaded.set(agent, source.description);
			if (headers.authorization === undefined) {
				// Nothing here can check what a token holder does to the set (see
				// `ownDecision`); without a token, that is anyone who reaches the port.
				context.logger.warn(
					{ engine: CEDAR_HTTP_ENGINE_NAME, endpoint },
					`cedar agent at ${endpoint} is used without a token — anything that reaches its port can replace the policy set, and every decision after it; set authentication (or ${CEDAR_AUTHENTICATION_ENV}), and start the agent with it`,
				);
			}

			try {
				await pushPolicies(
					doFetch,
					endpoint,
					headers,
					policies,
					source.description,
					context.logger,
					{
						loadTimeoutMs,
						retryMs,
					},
					tokenSourceOf(context.config.authentication, env[CEDAR_AUTHENTICATION_ENV]),
					maxAnswerBytes,
				);
			} catch (cause) {
				loaded.delete(agent);
				throw cause;
			}
			context.logger.info(
				{
					engine: CEDAR_HTTP_ENGINE_NAME,
					endpoint,
					policySet: source.description,
					policies: policies.length,
				},
				"cedar policy set loaded into the engine",
			);

			const policySet: AsyncCedarPolicySet = {
				async: true,
				async isAuthorized(request: CedarRequest, signal: AbortSignal): Promise<CedarDecision> {
					const call: AgentAuthorizationCall = {
						principal: entityUidLiteral(request.principal),
						action: entityUidLiteral(request.action),
						resource: entityUidLiteral(request.resource),
						context: request.context,
						entities: request.entities,
					};
					const response = await send(doFetch, `${endpoint}${IS_AUTHORIZED_PATH}`, {
						method: "POST",
						headers,
						body: JSON.stringify(call),
						signal,
						// Not followed (#270): a 3xx is the non-2xx it is, and fails closed
						// below. Followed, it re-sent the call — the subject's attributes —
						// wherever `Location` pointed and took that server's answer as the
						// decision, so a redirect could turn a forbid into an allow.
						redirect: "manual",
					});
					if (!response.ok) {
						const redirected = response.status >= 300 && response.status < 400;
						throw new CedarEngineError(
							`cedar engine at ${endpoint} answered ${response.status} to an authorization call: ${await errorDescription(response, maxAnswerBytes, signal)}${redirected ? " — redirects are not followed; set endpoint to the URL that answers it itself" : ""}`,
						);
					}
					return ownDecision(
						readDecision(
							parseJson(await answerText(response, signal, endpoint, maxAnswerBytes)),
							endpoint,
						),
						ownIds,
						ownMark,
					);
				},
			};
			return policySet;
		},
	};
}

/**
 * The id the agent holds a policy under (#283): its file id, and the load's
 * mark — the first 16 hex of the policy set's revision — after an `@`
 * (`10-permit-eng@9f2c…`). cedar-agent evaluates whatever set it holds, which
 * anyone with its token can replace, and names no revision; the ids of the
 * policies that determined an answer are all it gives back. Under this mark
 * those ids say which load they came from. It is the revision's own digest,
 * so replicas loading the same files push the same ids and do not take each
 * other's answers for foreign ones, while a replica with other files — a
 * rolling deploy sharing an agent, an agent restarted on its own set — does.
 */
export function agentPolicyId(id: string, revision: string): string {
	return `${id}${loadMark(revision)}`;
}

/** A load's mark as it follows an id: `@` and the revision's first 16 hex. */
function loadMark(revision: string): string {
	// 16 of the digest's hex — 64 bits, far past any collision two loads could
	// meet. The revision is always `sha256:<64 hex>` (computePolicyRevision).
	return `@${revision.slice(revision.indexOf(":") + 1).slice(0, 16)}`;
}

/**
 * An answer, read against what this load pushed (#283). Every policy it
 * names must be one of this load's, under its mark — each determining policy,
 * and the policy each evaluation error names; then the answer names the
 * determining ones by their file ids, each once — so it can name no more than
 * were pushed. One that is not — no mark, another load's, an id never pushed,
 * an item that is not an id at all — means the answer did not come from this
 * set: it is marked `foreign`, and names nothing of it. The errors count as
 * much as the reason: a set this verifier did not load can answer with errors
 * alone, and they would otherwise be logged as this load's.
 *
 * The errors stay the agent's text, marked ids and all, for the log.
 *
 * The mark is no secret and no authenticator: the ids are in every answer, in
 * the agent's `GET /v1/policies`, and computable from the policy files. It
 * catches a set this verifier did not load — replaced, shared, reloaded — not
 * someone holding the agent's token, who can rewrite a policy under its own
 * marked id, or delete one, and be answered for as this load. No check of an
 * answer can see that; the agent's token is the boundary.
 */
function ownDecision(
	{ decision, errorItems }: AgentAnswer,
	ownIds: ReadonlyMap<string, string>,
	ownMark: string,
): CedarDecision {
	const reason: string[] = [];
	const seen = new Set<string>();
	for (const item of decision.reason) {
		const id = ownIds.get(item);
		if (id === undefined) {
			return { ...decision, reason: [], foreign: foreignAnswer(item, ownIds) };
		}
		if (seen.has(id)) continue;
		seen.add(id);
		reason.push(id);
	}
	for (const item of errorItems) {
		const policy = erroringPolicy(item, ownMark);
		if (policy !== undefined && !ownIds.has(policy)) {
			return { ...decision, reason: [], foreign: foreignAnswer(policy, ownIds) };
		}
	}
	return { ...decision, reason };
}

/**
 * The start of an evaluation error as cedar-agent's Cedar words it, up to the
 * policy id: `error occurred while evaluating policy` in cedar-policy 2.5
 * (cedar-agent 0.2.2), `error while evaluating policy` in 4.x.
 */
const EVALUATION_ERROR = /^error (?:occurred )?while evaluating policy `/;

/**
 * The one error Cedar 2.5 raises before any policy is evaluated — an entity
 * or context attribute it could not evaluate. It names no policy, this load's
 * or another's, so it says nothing of which set answered. (4.x has no such
 * error; this engine sends no extension values that could raise it today.)
 */
const ATTRIBUTE_EVALUATION_ERROR = "error occurred while evaluating entity attributes: ";

/**
 * The policy an evaluation error names, or `undefined` for the one error that
 * names none: the id in an error string, or the `policyId` of a structured
 * one (Cedar 3.x+). An item that names no id it can read is
 * {@link UNREADABLE_POLICY_ID}, no policy of this load's.
 *
 * In a string, Cedar prints the id through Rust's `escape_debug` — in
 * `diagnostics.reason` it is sent raw — so it is unescaped to compare. And a
 * backtick is not escaped: a file named `` a`: b.cedar `` holds the `` `: ``
 * that ends an id. So an id of this load's is read to where this load's mark
 * ends it; any other, to the first `` `: ``. Either way the slice starts at
 * the id, so the message after it — which may carry the request's values —
 * cannot make another set's id read as this load's.
 */
function erroringPolicy(item: unknown, ownMark: string): string | undefined {
	if (typeof item === "string") {
		if (item.startsWith(ATTRIBUTE_EVALUATION_ERROR)) return undefined;
		const start = EVALUATION_ERROR.exec(item);
		if (start === null) return UNREADABLE_POLICY_ID;
		const from = start[0].length;
		const own = item.indexOf(`${ownMark}\`: `, from);
		const end = own !== -1 ? own + ownMark.length : item.indexOf("`: ", from);
		return end === -1 ? UNREADABLE_POLICY_ID : unescapeDebug(item.slice(from, end));
	}
	const policyId = (item as { policyId?: unknown } | null)?.policyId;
	return typeof policyId === "string" ? policyId : UNREADABLE_POLICY_ID;
}

/**
 * Undoes Rust's `str::escape_debug`: `\0 \t \r \n \\ \" \'` and `\u{…}`, which
 * is everything it writes a backslash for — so the inverse is exact. Any other
 * backslash is left as it is: no `escape_debug` wrote it.
 */
function unescapeDebug(text: string): string {
	return text.replace(/\\(?:u\{([0-9a-f]{1,6})\}|([0tnr\\"']))/g, (written, hex, char) => {
		if (hex === undefined) return DEBUG_ESCAPES[char as keyof typeof DEBUG_ESCAPES];
		const codePoint = Number.parseInt(hex, 16);
		return codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : written;
	});
}

const DEBUG_ESCAPES = { "0": "\0", t: "\t", r: "\r", n: "\n", "\\": "\\", '"': '"', "'": "'" };

/**
 * Why `item` is not this load's: a fixed label, and — only when `item` is one
 * of this load's own file ids under another 16-hex mark — that mark. A file
 * may be named `x@<16 hex>.cedar`, so a suffix alone says nothing; one of this
 * load's names under a different mark is another load of the same corpus.
 */
function foreignAnswer(item: string, ownIds: ReadonlyMap<string, string>): ForeignAnswer {
	if (item.startsWith(UNREADABLE_POLICY_ID)) return { why: "unreadable policy" };
	const marked = /^(.*)@([0-9a-f]{16})$/.exec(item);
	if (marked !== null && [...ownIds.values()].includes(marked[1])) {
		return { why: "unknown policy", mark: marked[2] };
	}
	return { why: "unknown policy" };
}

/** The engine a deployment gets by naming `engine = "http"`, or by default when the wasm package is not imported. */
export const cedarHttpEngine: CedarEngine = createCedarHttpEngine();

// --- boot ---------------------------------------------------------------------

async function pushPolicies(
	doFetch: typeof fetch,
	endpoint: string,
	headers: Record<string, string>,
	policies: ReadonlyArray<{ id: string; content: string }>,
	description: string,
	logger: Logger,
	timing: { loadTimeoutMs: number; retryMs: number },
	tokenSource: string | undefined,
	maxAnswerBytes: number,
): Promise<void> {
	const { loadTimeoutMs, retryMs } = timing;
	const deadline = Date.now() + loadTimeoutMs;
	let attempt = 0;
	/** How the previous attempt failed, when it did — for a timeout to name. */
	let previousFailure: string | undefined;
	for (;;) {
		attempt++;
		const attemptSignal = AbortSignal.timeout(Math.max(1, deadline - Date.now()));
		let response: Response;
		try {
			response = await doFetch(`${endpoint}${POLICIES_PATH}`, {
				method: "PUT",
				headers,
				body: JSON.stringify(policies),
				signal: attemptSignal,
				// Not followed (#270): the policy set goes to the configured endpoint
				// or nowhere.
				redirect: "manual",
			});
		} catch (cause) {
			// The attempt's own signal is the load deadline, told by the signal
			// and not by the name of what `fetch` threw. It proves only that no
			// answer came in time, not that the agent is reachable (#271): a
			// retry runs on what is left of the deadline — a millisecond, when a
			// timer overshoots — and can time out before its refusal arrives, and
			// a host that drops packets never completes the connection at all.
			// So the message says what is known, and names how the attempt before
			// failed when one did.
			if (attemptSignal.aborted) {
				throw new CedarEngineError(
					`cedar engine at ${endpoint} did not accept the policy set from ${description} within ${loadTimeoutMs} ms (${attempt} attempts) — ${
						previousFailure === undefined
							? "the request got no response before the deadline: the agent took it and did not answer, or the connection never completed"
							: `the last got no response before the deadline, and the one before it failed: ${previousFailure}`
					}`,
				);
			}
			// Unreachable, not refused: a compose sibling may still be starting.
			// Retry until the deadline, then fail boot naming the endpoint.
			previousFailure = describeFailure(cause);
			if (Date.now() + retryMs >= deadline) {
				throw new CedarEngineError(
					`cedar engine at ${endpoint} is unreachable — could not load the policy set from ${description} within ${loadTimeoutMs} ms (${attempt} attempts): ${previousFailure}`,
				);
			}
			logger.warn(
				{ engine: CEDAR_HTTP_ENGINE_NAME, endpoint, attempt, reason: previousFailure },
				"cedar engine unreachable, retrying",
			);
			await new Promise((resolve) => setTimeout(resolve, retryMs));
			continue;
		}
		if (response.ok) return;
		if (response.status >= 300 && response.status < 400) {
			// Not retried: the endpoint is configuration, and it did not answer
			// the load itself.
			await response.body?.cancel().catch(() => undefined);
			throw new CedarEngineError(
				`cedar engine at ${endpoint} answered ${response.status} to the policy load instead of accepting it — redirects are not followed; set endpoint to the URL that answers it itself`,
			);
		}
		if (response.status === 401 || response.status === 403) {
			// The agent's own body says only "requires user authentication"; the
			// fix is on this side, so name it (v0.10.0 audit — the template starts
			// the agent with CEDAR_AGENT_AUTHENTICATION from CEDAR_AUTHENTICATION).
			await response.body?.cancel().catch(() => undefined);
			throw new CedarEngineError(
				headers.authorization === undefined
					? `cedar engine at ${endpoint} requires a token and none was sent — set authentication (or ${CEDAR_AUTHENTICATION_ENV}) to the token the agent was started with (${response.status})`
					: `cedar engine at ${endpoint} did not accept the token from ${tokenSource ?? "authentication"} (${response.status}) — it must equal the agent's --authentication / CEDAR_AGENT_AUTHENTICATION`,
			);
		}
		// The agent answered and said no: a policy it cannot parse (400). Not
		// retried — nothing will change.
		// The agent's message does not say which policy, so the ids that were
		// sent are listed; with one policy per file, that is the file list.
		const ids = policies.map((policy) => policy.id).join(", ") || "none";
		throw new CedarEngineError(
			`cedar engine at ${endpoint} refused the policy set from ${description} (${response.status}; policies: ${ids}): ${await errorDescription(response, maxAnswerBytes)}`,
		);
	}
}

// --- the endpoint -------------------------------------------------------------

/**
 * The server package's `isLoopbackHost` rule, restated because this package
 * depends on core only: the whole 127.0.0.0/8 block with range-checked
 * octets, `localhost`, and the IPv6 loopback — `URL.hostname` keeps the
 * brackets (`[::1]`), the bare form is accepted for a runtime that strips
 * them. An exact test, never a prefix or suffix one: `localhost.attacker.test`
 * and `127.0.0.1.attacker.test` are ordinary routable names.
 */
const LOOPBACK_IPV4 = /^127(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function isLoopbackHost(hostname: string): boolean {
	return (
		hostname === "localhost" ||
		hostname === "[::1]" ||
		hostname === "::1" ||
		LOOPBACK_IPV4.test(hostname)
	);
}

/**
 * What identifies an agent for "one collector per agent" (v0.10.0 audit): the
 * endpoint with every loopback spelling — `localhost`, `127.0.0.0/8`, `[::1]` —
 * read as one host and the default port made explicit. Keyed on the string,
 * `http://127.0.0.1:8180` and `http://localhost:8180` were two agents, and the
 * second collector silently replaced the first's policy set. Two loopback
 * addresses could in principle be two agents on one port; treating them as
 * one only ever refuses a boot, never overwrites a set.
 */
function agentKey(endpoint: string): string {
	const url = new URL(endpoint);
	const port = url.port || (url.protocol === "https:" ? "443" : "80");
	const host = isLoopbackHost(url.hostname) ? "loopback" : url.hostname;
	return `${url.protocol}//${host}:${port}${url.pathname}`;
}

function resolveEndpoint(configured: unknown, fromEnv: string | undefined): string {
	let raw: string;
	let origin: string;
	if (configured !== undefined) {
		if (typeof configured !== "string" || configured.length === 0) {
			throw new CedarEngineError(
				`endpoint must be a non-empty URL string, got ${shown(configured)}`,
			);
		}
		raw = configured;
		origin = "config endpoint";
	} else if (fromEnv !== undefined && fromEnv.length > 0) {
		raw = fromEnv;
		origin = CEDAR_ENDPOINT_ENV;
	} else {
		throw new CedarEngineError(
			`no cedar engine endpoint is configured — set endpoint (or ${CEDAR_ENDPOINT_ENV}) to run against a cedar-agent, or import "@o3co/auth.policy-verifier.cedar-wasm" to evaluate in-process`,
		);
	}

	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		throw new CedarEngineError(`${origin} is not a URL: ${JSON.stringify(raw)}`);
	}
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new CedarEngineError(`${origin} must be an http(s) URL, got ${JSON.stringify(raw)}`);
	}
	if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) {
		throw new CedarEngineError(
			`${origin} is plain http to a routable host (${url.hostname}); the request carries the subject's attributes and the answer is an authorization — use https, or a loopback address`,
		);
	}
	if (url.search !== "" || url.hash !== "") {
		throw new CedarEngineError(
			`${origin} must be a base URL without query or fragment, got ${JSON.stringify(raw)}`,
		);
	}
	// `url.origin` would silently drop them, and a token belongs in the header anyway.
	if (url.username !== "" || url.password !== "") {
		throw new CedarEngineError(
			`${origin} must not carry credentials in the URL — set authentication (or ${CEDAR_AUTHENTICATION_ENV}) instead`,
		);
	}
	// A base URL: the agent's paths are appended, so a trailing slash would double up.
	return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/**
 * The range `maxAnswerBytes` may be set in. Below 1 KiB a bound saves no
 * memory worth having and is almost certainly a unit slip — `4` meant as MiB,
 * `512` meant as KiB. The smallest decision is about 60 bytes and grows with
 * each determining policy and error, so such a bound denies some answers or
 * all of them, and only once requests arrive; refused at boot instead. Above
 * 256 MiB the text would approach the longest string V8 can hold, about
 * 512 Mi characters, and a failure there would be reported as a broken-off
 * answer.
 */
const MIN_ANSWER_BYTES = 1024;
const MAX_ANSWER_BYTES = 256 * 1024 * 1024;

/**
 * The collector entry's `maxAnswerBytes`, else {@link CEDAR_ANSWER_MAX_BYTES}.
 * Written as a number or a numeric string — what a HOCON env substitution of
 * the operator's own variable (`${?MY_ANSWER_BYTES}`) delivers — the rule the
 * server's numeric knobs follow (`resolveBound` in the server package, which
 * this package cannot import), and a whole number of bytes in range. Checked
 * here, where `endpoint` is: the config schema passes a collector entry
 * through, so the engine is where its keys are checked
 * (`CedarEngineLoadContext.config`). `null` is a value, and refused like
 * anything else that is not a byte count.
 */
function resolveMaxAnswerBytes(configured: unknown): number {
	if (configured === undefined) return CEDAR_ANSWER_MAX_BYTES;
	const bytes = isWrittenAsNumber(configured) ? Number(configured) : Number.NaN;
	if (!Number.isSafeInteger(bytes) || bytes < MIN_ANSWER_BYTES || bytes > MAX_ANSWER_BYTES) {
		throw new CedarEngineError(
			`maxAnswerBytes must be a whole number of bytes from ${byteSize(MIN_ANSWER_BYTES)} to ${byteSize(MAX_ANSWER_BYTES)}, got ${shown(configured)}`,
		);
	}
	return bytes;
}

/** The two forms a number is written in: a number, or a non-blank string. `Number(true)` is 1. */
function isWrittenAsNumber(value: unknown): value is number | string {
	return typeof value === "number" || (typeof value === "string" && value.trim() !== "");
}

/** A config value as a refusal quotes it — any value, a bigint or a symbol included. */
function shown(value: unknown): string {
	if (typeof value === "number") return String(value);
	if (typeof value === "bigint") return `${value}n`;
	if (typeof value === "symbol") return value.toString();
	try {
		return JSON.stringify(value) ?? String(value);
	} catch {
		// A circular object, or one with no toString: say what it is.
		return Object.prototype.toString.call(value);
	}
}

/** A byte count as an operator would write it: MiB or KiB when it divides evenly, else bytes. */
function byteSize(bytes: number): string {
	if (bytes % (1024 * 1024) === 0) return `${bytes / (1024 * 1024)} MiB`;
	if (bytes % 1024 === 0) return `${bytes / 1024} KiB`;
	return `${bytes} bytes`;
}

/** Where the token sent to the agent came from, for a refusal to name — or `undefined` when none is sent. */
function tokenSourceOf(configured: unknown, fromEnv: string | undefined): string | undefined {
	if (configured !== undefined) return "authentication";
	return fromEnv !== undefined && fromEnv.length > 0 ? CEDAR_AUTHENTICATION_ENV : undefined;
}

function requestHeaders(configured: unknown, fromEnv: string | undefined): Record<string, string> {
	const headers: Record<string, string> = { "content-type": "application/json" };
	let token: string | undefined;
	if (configured !== undefined) {
		if (typeof configured !== "string" || configured.length === 0) {
			throw new CedarEngineError(
				`authentication must be a non-empty string, got ${shown(configured)}`,
			);
		}
		token = configured;
	} else if (fromEnv !== undefined && fromEnv.length > 0) {
		token = fromEnv;
	}
	if (token !== undefined && !isSendableHeaderValue(token)) {
		throw new CedarEngineError(
			`${configured !== undefined ? "authentication" : CEDAR_AUTHENTICATION_ENV} is not a valid HTTP header value — it holds an ASCII control character other than a tab, or a character above U+00FF; set it to the token the agent was started with`,
		);
	}
	// cedar-agent compares the header to its `--authentication` value verbatim: no scheme.
	if (token !== undefined) headers.authorization = token;
	return headers;
}

/**
 * Whether `fetch` can send `value` as a header value — undici's last rule:
 * once the tabs, spaces and line breaks around it are trimmed, which `fetch`
 * does itself, a tab, printable ASCII or U+0080–U+00FF and nothing else. So a
 * token read from a file with its trailing newline still goes. `fetch`
 * refuses anything else — quoting the value for a line break or a NUL — and
 * the load would have called the agent unreachable (#271).
 */
function isSendableHeaderValue(value: string): boolean {
	const trimmed = value.replace(/^[\t\n\r ]+|[\t\n\r ]+$/g, "");
	for (const char of trimmed) {
		const code = char.codePointAt(0) as number;
		const sendable =
			code === 0x09 || (code >= 0x20 && code <= 0x7e) || (code >= 0x80 && code <= 0xff);
		if (!sendable) return false;
	}
	return true;
}

// --- the wire ------------------------------------------------------------------

async function send(doFetch: typeof fetch, url: string, init: RequestInit): Promise<Response> {
	try {
		return await doFetch(url, init);
	} catch (cause) {
		// The rule's signal aborting is the caller's or the deadline's doing; the
		// evaluator maps that itself. Everything else is the engine not answering.
		if (init.signal?.aborted) throw init.signal.reason;
		throw new CedarEngineError(`cedar engine at ${url} is unreachable: ${describeFailure(cause)}`);
	}
}

/**
 * The body of a 2xx answer, read whole. The status arrives before the body,
 * and the read can fail in between (#271): an abort — the rule deadline, or
 * the caller leaving — rejects with the signal's reason, as it does before the
 * status, since that is how the collector and any other caller of the port
 * tell a timeout from an outage; any other failure is the answer broken off,
 * not an answer that is not a decision.
 */
async function answerText(
	response: Response,
	signal: AbortSignal,
	endpoint: string,
	maxAnswerBytes: number,
): Promise<string> {
	let text: string | typeof OVER_BOUND;
	try {
		text = await boundedText(response, maxAnswerBytes);
	} catch (cause) {
		if (signal.aborted) throw signal.reason;
		throw new CedarEngineError(
			`cedar engine at ${endpoint} broke off its answer to an authorization call: ${describeFailure(cause)}`,
		);
	}
	if (text === OVER_BOUND) {
		throw new CedarEngineError(
			`cedar engine at ${endpoint} answered an authorization call with more than ${byteSize(maxAnswerBytes)} — refused; set maxAnswerBytes higher if its answers are this large`,
		);
	}
	return text;
}

/** What {@link boundedText} returns for a body past its bound. */
const OVER_BOUND = Symbol("over the answer bound");

/**
 * A body read whole and decoded as UTF-8 with one leading BOM dropped, as the
 * Fetch standard's `text()` does, up to `maxBytes`. Past that — declared by
 * `content-length`, or found while streaming — the read stops, the body is
 * cancelled, and {@link OVER_BOUND} comes back. A failed read rejects as the
 * stream does.
 */
async function boundedText(
	response: Response,
	maxBytes: number,
): Promise<string | typeof OVER_BOUND> {
	if (Number(response.headers.get("content-length")) > maxBytes) {
		await response.body?.cancel().catch(() => undefined);
		return OVER_BOUND;
	}
	if (response.body === null) return "";
	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let text = "";
	let received = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) return text + decoder.decode();
		received += value.byteLength;
		if (received > maxBytes) {
			await reader.cancel().catch(() => undefined);
			return OVER_BOUND;
		}
		text += decoder.decode(value, { stream: true });
	}
}

/** The body as JSON, or `undefined` for anything that is not — which `readDecision` refuses. */
function parseJson(text: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
}

/**
 * cedar-agent's error body is `{ reason, description, code }`; fall back to
 * the status text. The status is the fact, so a body that does not arrive, or
 * is over the bound, leaves it to the status text, unless the read was cut by
 * `signal` aborting, which is the signal's to report (#271). The bound is
 * `maxAnswerBytes`, and never more than {@link CEDAR_ANSWER_MAX_BYTES}.
 */
async function errorDescription(
	response: Response,
	maxAnswerBytes: number,
	signal?: AbortSignal,
): Promise<string> {
	let text: string | typeof OVER_BOUND | undefined;
	try {
		// Raising maxAnswerBytes is for decisions; an error's body becomes the
		// log line, so it stays under the default however high that is set.
		text = await boundedText(response, Math.min(maxAnswerBytes, CEDAR_ANSWER_MAX_BYTES));
	} catch {
		if (signal?.aborted) throw signal.reason;
	}
	const body = typeof text === "string" ? parseJson(text) : undefined;
	if (typeof body === "object" && body !== null) {
		const description = (body as Record<string, unknown>).description;
		if (typeof description === "string" && description.length > 0) return description;
	}
	return response.statusText || "no description";
}

/**
 * A decision as the agent answered it, and its errors as it sent them: each
 * names the policy that raised it, but for the one that names none
 * ({@link ATTRIBUTE_EVALUATION_ERROR}).
 */
interface AgentAnswer {
	decision: CedarDecision;
	errorItems: readonly unknown[];
}

/** Reads cedar-agent's `AuthorizationAnswer`; anything else is the engine not answering. */
function readDecision(body: unknown, endpoint: string): AgentAnswer {
	if (typeof body !== "object" || body === null) {
		throw new CedarEngineError(
			`cedar engine at ${endpoint} answered something that is not a decision`,
		);
	}
	const { decision, diagnostics } = body as Record<string, unknown>;
	const normalized = typeof decision === "string" ? decision.toLowerCase() : undefined;
	if (normalized !== "allow" && normalized !== "deny") {
		throw new CedarEngineError(
			`cedar engine at ${endpoint} answered an unknown decision ${JSON.stringify(decision)}`,
		);
	}
	// Both lists are required, as cedar-agent always sends them: an answer
	// without them is some other shape, and "no errors" must not be inferred
	// from a field that is not there — that is the fail-open direction.
	const reason = policyIds((diagnostics as Record<string, unknown> | undefined)?.reason);
	const errorItems = (diagnostics as Record<string, unknown> | undefined)?.errors;
	const errors = renderedList(errorItems);
	if (
		typeof diagnostics !== "object" ||
		diagnostics === null ||
		reason === undefined ||
		errors === undefined
	) {
		throw new CedarEngineError(
			`cedar engine at ${endpoint} answered a decision without well-formed diagnostics`,
		);
	}
	return {
		decision: { decision: normalized, reason, errors },
		errorItems: errorItems as unknown[],
	};
}

/**
 * `diagnostics.reason` as policy ids, or `undefined` when it is not a list.
 *
 * The ids are what a decision's `determiningPolicies` names (#199), so an item
 * is read, not rendered: a string is the id, and an object carrying a string
 * `policyId` — the structured form Cedar gives an error — yields that. Any
 * other item is kept as its JSON behind a NUL, which no policy id is: the
 * answer is then read as not this load's (`ownDecision`, #283), since a permit
 * that cannot be named cannot be attributed — `"unreadable policy"`, told
 * apart in the log from a policy this load never pushed. An agent image that
 * changed the shape of its reason items would so deny every permit, loudly
 * and saying why; before #283 such items were only counted. The list itself
 * stays required.
 */
function policyIds(value: unknown): string[] | undefined {
	if (!Array.isArray(value)) return undefined;
	return value.map((item) => {
		if (typeof item === "string") return item;
		const policyId = (item as { policyId?: unknown } | null)?.policyId;
		return typeof policyId === "string" ? policyId : UNREADABLE_POLICY_ID + JSON.stringify(item);
	});
}

/** Marks a reason or error item that names no id this engine can read: a control character, which no reportable id holds. */
const UNREADABLE_POLICY_ID = "\u0000";

/**
 * A diagnostics list as rendered text, or `undefined` when it is not a list.
 *
 * The items are strings from cedar-agent 0.2.x (cedar-policy 2.5); Cedar 3.x+
 * serialises errors as objects. The rule only logs errors and decides on
 * whether there are any — which rendering cannot change — so a non-string
 * item is rendered rather than the whole answer refused (v0.10.0 audit). The
 * list itself stays required.
 */
function renderedList(value: unknown): string[] | undefined {
	if (!Array.isArray(value)) return undefined;
	return value.map((item) =>
		typeof item === "string" ? item : (JSON.stringify(item) ?? String(item)),
	);
}

/** A Cedar entity type: an identifier path, `App::User` — nothing else may reach the wire. */
const CEDAR_TYPE_PATH = /^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$/;

/**
 * Renders an entity reference in Cedar's own syntax — `User::"alice"` — which
 * is how cedar-agent's `AuthorizationCall` takes principal, action and
 * resource. The type must be a Cedar identifier path (it comes from config
 * and from the `requestResourceType` attribute, so it is checked here rather
 * than trusted); anything else throws {@link CedarEngineError}, which inside
 * `isAuthorized` is a logged deny before any request is sent. The id is a
 * Cedar string literal: `\` and `"` escaped, `\n` `\r` `\t` `\0` as their
 * short escapes, every other control character as `\u{…}`.
 */
export function entityUidLiteral(uid: CedarEntityUid): string {
	if (!CEDAR_TYPE_PATH.test(uid.type)) {
		throw new CedarEngineError(
			`entity type ${JSON.stringify(uid.type)} is not a Cedar entity type path (Ident, or Ident::Ident…)`,
		);
	}
	return `${uid.type}::${cedarStringLiteral(uid.id)}`;
}

function cedarStringLiteral(value: string): string {
	let out = '"';
	for (const char of value) {
		const code = char.codePointAt(0) as number;
		if (char === "\\") out += "\\\\";
		else if (char === '"') out += '\\"';
		else if (char === "\n") out += "\\n";
		else if (char === "\r") out += "\\r";
		else if (char === "\t") out += "\\t";
		else if (char === "\0") out += "\\0";
		else if (code < 0x20 || code === 0x7f) out += `\\u{${code.toString(16)}}`;
		else out += char;
	}
	return `${out}"`;
}

/** How many links of a `cause` chain a message follows, and how long one link may run. */
const FAILURE_DEPTH = 4;
const FAILURE_LINK_MAX = 200;

/** A link that could not be read — no `toString`, a getter that throws — named as such. */
const UNDESCRIBABLE = "a failure that could not be described";

/**
 * A failure as one line, its causes included (#271). The real `fetch` rejects
 * with "fetch failed" whatever happened, and keeps what did — a refusal, a
 * name that does not resolve, a TLS error, a reset — on `cause`; the message
 * alone reads the same for all of them. Each link is its message with
 * whitespace collapsed (OpenSSL's spans lines), led by its `code` when the
 * message does not carry it already, and cut at {@link FAILURE_LINK_MAX}
 * characters; an `AggregateError` without a message — one error per address
 * tried, as `localhost` gives — is its errors. At most {@link FAILURE_DEPTH}
 * links, each object once. Describing never throws: whatever a `fetch`
 * rejected with, the caller still raises its `CedarEngineError`.
 *
 * Only messages and codes are read, never the request. `fetch`'s one error
 * that quotes a header — an invalid value — cannot arise for the token, which
 * load refuses unless `fetch` can send it; a custom `fetch`'s messages are
 * its own.
 */
function describeFailure(failure: unknown): string {
	const seen = new Set<unknown>();
	const links: string[] = [];
	let link: unknown = failure;
	// Counted per link visited, not per link that said something: a `cause`
	// getter can hand over a fresh, empty error every time it is read.
	for (let visited = 0; visited < FAILURE_DEPTH; visited++) {
		if (link === undefined || link === null || seen.has(link)) break;
		seen.add(link);
		const text = describeLink(link, seen, 1);
		if (text.length > 0) links.push(text);
		link = causeOf(link);
	}
	return links.join(": ") || "no description";
}

function describeLink(failure: unknown, seen: Set<unknown>, depth: number): string {
	try {
		if (!(failure instanceof Error)) return clip(collapse(String(failure)));
		let text = collapse(failure.message);
		if (text.length === 0 && failure instanceof AggregateError && depth < FAILURE_DEPTH) {
			// By index, and counted per error tried: the array's own iterator
			// is not the engine's to trust.
			const errors: unknown[] = Array.isArray(failure.errors) ? failure.errors : [];
			const parts: string[] = [];
			for (let index = 0; index < Math.min(errors.length, FAILURE_DEPTH); index++) {
				const error = errors[index];
				if (seen.has(error)) continue;
				seen.add(error);
				const part = describeLink(error, seen, depth + 1);
				if (part.length > 0) parts.push(part);
			}
			text = parts.join("; ");
		}
		const code = (failure as { code?: unknown }).code;
		if (typeof code === "string" && code.length > 0 && !text.includes(code)) {
			text = text.length > 0 ? `${code}: ${text}` : code;
		}
		return clip(text);
	} catch {
		return UNDESCRIBABLE;
	}
}

/** `failure.cause`, or `undefined` when there is none or it cannot be read. */
function causeOf(failure: unknown): unknown {
	try {
		return failure instanceof Error ? failure.cause : undefined;
	} catch {
		return undefined;
	}
}

function collapse(text: string): string {
	return text.replace(/\s+/g, " ").trim();
}

function clip(text: string): string {
	return text.length > FAILURE_LINK_MAX ? `${text.slice(0, FAILURE_LINK_MAX - 1)}…` : text;
}
