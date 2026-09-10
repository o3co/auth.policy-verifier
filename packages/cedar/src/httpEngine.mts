// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { basename } from "node:path";
import type { Logger } from "@o3co/auth.policy-verifier.core";
import type { CedarEntityUid } from "./cedarJson.mjs";
import {
	type AsyncCedarPolicySet,
	type CedarDecision,
	type CedarEngine,
	CedarEngineError,
	type CedarEngineLoadContext,
} from "./engine.mjs";
import type { CedarRequest } from "./mapping.mjs";
import type { PolicySource } from "./policySource.mjs";

/** The name this engine registers under, and the config value that selects it. */
export const CEDAR_HTTP_ENGINE_NAME = "http" as const;

/**
 * Where the engine looks when neither config nor environment says: the
 * loopback address and port the standalone template's `cedar-engine` compose
 * service listens on (cedar-agent's own default port). Shared network
 * namespace, so loopback is the whole trust boundary — the same one the
 * verifier's own bind address draws.
 */
export const DEFAULT_CEDAR_ENDPOINT = "http://127.0.0.1:8180";

/** Environment variable that overrides the endpoint when config does not set it. */
export const CEDAR_ENDPOINT_ENV = "CEDAR_ENDPOINT";

/** Environment variable carrying the agent's `Authorization` token, when it enforces one. */
export const CEDAR_AUTHENTICATION_ENV = "CEDAR_AUTHENTICATION";

/** How long boot waits for the engine to accept the policy set, retrying while it is unreachable. */
export const CEDAR_LOAD_TIMEOUT_MS = 10_000;

const LOAD_RETRY_MS = 500;
const POLICIES_PATH = "/v1/policies";
const IS_AUTHORIZED_PATH = "/v1/is_authorized";

/** Constructor options, for composition and tests; the registered engine uses the defaults. */
export interface CedarHttpEngineOptions {
	/** The `fetch` to call. Defaults to the global one, looked up per call. */
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
 * entry per file, the file's name as the policy id — so the agent holds
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
 * `endpoint` in the collector's config entry, else `CEDAR_ENDPOINT`, else
 * {@link DEFAULT_CEDAR_ENDPOINT} — the loopback address the template's
 * `cedar-engine` compose service answers on. A base URL: the two paths above
 * are appended. Plain `http://` is accepted for loopback hosts only; anything
 * routable must be `https://`, the rule `jwksUri` follows, because the wire
 * carries the request's attributes and the agent's answer is an authorization.
 * `authentication` in config, else `CEDAR_AUTHENTICATION`, is sent verbatim as
 * the `Authorization` header — the value the agent was started with.
 *
 * ## What it asks of the policy set
 *
 * cedar-agent stores policies one by one, so **each `.cedar` file must hold
 * exactly one policy** (and inline `policies` one policy); a file with two is
 * refused at boot with the agent's message. The wasm engine concatenates and
 * does not care — a policy corpus laid out one policy per file works under
 * both, and reads better under this one, because `diagnostics.reason` then
 * names files rather than `policy0`. `PUT /v1/policies` replaces the agent's
 * whole set, so one collector per agent: a second `load` against the same
 * endpoint is refused rather than silently overwriting the first.
 *
 * ## Failure is loud and closed
 *
 * Boot retries a connection refusal for {@link CEDAR_LOAD_TIMEOUT_MS} (a
 * compose sibling may be a few hundred milliseconds behind) and then refuses
 * to start. After boot, an agent that is unreachable, answers non-2xx or
 * answers something that is not a decision rejects with
 * {@link CedarEngineError}; the collector logs it and denies, never abstains.
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

		async load(source: PolicySource, context: CedarEngineLoadContext) {
			const endpoint = resolveEndpoint(context.config.endpoint, env[CEDAR_ENDPOINT_ENV]);
			const headers = requestHeaders(context.config.authentication, env[CEDAR_AUTHENTICATION_ENV]);

			const holder = loaded.get(endpoint);
			if (holder !== undefined) {
				throw new CedarEngineError(
					`cedar engine at ${endpoint} already holds the policy set from ${holder} — PUT /v1/policies replaces an agent's whole set, so run one CedarPolicyRuleCollector per agent`,
				);
			}
			// Reserved before the first request, not after the last: two collectors
			// loading concurrently must not both pass the check above.
			loaded.set(endpoint, source.description);

			const nonBlank = source.files.filter((file) => file.text.trim().length > 0);
			const policies = nonBlank.map((file) => ({ id: policyId(file.source), content: file.text }));
			for (const [index, policy] of policies.entries()) {
				if (policy.id.length === 0) {
					loaded.delete(endpoint);
					throw new CedarEngineError(
						`"${nonBlank[index].source}" yields an empty policy id — the file needs a name before .cedar`,
					);
				}
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
				);
			} catch (cause) {
				loaded.delete(endpoint);
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
					});
					if (!response.ok) {
						throw new CedarEngineError(
							`cedar engine at ${endpoint} answered ${response.status} to an authorization call: ${await errorDescription(response)}`,
						);
					}
					return readDecision(await response.json().catch(() => undefined), endpoint);
				},
			};
			return policySet;
		},
	};
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
): Promise<void> {
	const { loadTimeoutMs, retryMs } = timing;
	const deadline = Date.now() + loadTimeoutMs;
	let attempt = 0;
	for (;;) {
		attempt++;
		let response: Response;
		try {
			response = await doFetch(`${endpoint}${POLICIES_PATH}`, {
				method: "PUT",
				headers,
				body: JSON.stringify(policies),
				signal: AbortSignal.timeout(Math.max(1, deadline - Date.now())),
			});
		} catch (cause) {
			// The request's own signal is the load deadline, so a timeout means an
			// agent that is reachable but not answering — said as such, since it
			// is a different thing to troubleshoot than a connection refused.
			if (cause instanceof Error && cause.name === "TimeoutError") {
				throw new CedarEngineError(
					`cedar engine at ${endpoint} did not accept the policy set from ${description} within ${loadTimeoutMs} ms — reachable, but the request timed out (${attempt} attempts)`,
				);
			}
			// Unreachable, not refused: a compose sibling may still be starting.
			// Retry until the deadline, then fail boot naming the endpoint.
			if (Date.now() + retryMs >= deadline) {
				throw new CedarEngineError(
					`cedar engine at ${endpoint} is unreachable — could not load the policy set from ${description} within ${loadTimeoutMs} ms (${attempt} attempts): ${errorMessage(cause)}`,
				);
			}
			logger.warn(
				{ engine: CEDAR_HTTP_ENGINE_NAME, endpoint, attempt, reason: errorMessage(cause) },
				"cedar engine unreachable, retrying",
			);
			await new Promise((resolve) => setTimeout(resolve, retryMs));
			continue;
		}
		if (response.ok) return;
		// The agent answered and said no: a policy it cannot parse (400), a
		// token it does not accept (401). Not retried — nothing will change.
		// The agent's message does not say which policy, so the ids that were
		// sent are listed; with one policy per file, that is the file list.
		const ids = policies.map((policy) => policy.id).join(", ") || "none";
		throw new CedarEngineError(
			`cedar engine at ${endpoint} refused the policy set from ${description} (${response.status}; policies: ${ids}): ${await errorDescription(response)}`,
		);
	}
}

/** cedar-agent policy ids are free-form; the file name reads best in `diagnostics.reason`. */
function policyId(source: string): string {
	if (source === "policies (inline)") return "policies";
	return basename(source).replace(/\.cedar$/, "");
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

function resolveEndpoint(configured: unknown, fromEnv: string | undefined): string {
	let raw: string;
	let origin: string;
	if (configured !== undefined) {
		if (typeof configured !== "string" || configured.length === 0) {
			throw new CedarEngineError(
				`endpoint must be a non-empty URL string, got ${JSON.stringify(configured)}`,
			);
		}
		raw = configured;
		origin = "config endpoint";
	} else if (fromEnv !== undefined && fromEnv.length > 0) {
		raw = fromEnv;
		origin = CEDAR_ENDPOINT_ENV;
	} else {
		raw = DEFAULT_CEDAR_ENDPOINT;
		origin = "the default";
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

function requestHeaders(configured: unknown, fromEnv: string | undefined): Record<string, string> {
	const headers: Record<string, string> = { "content-type": "application/json" };
	let token: string | undefined;
	if (configured !== undefined) {
		if (typeof configured !== "string" || configured.length === 0) {
			throw new CedarEngineError(
				`authentication must be a non-empty string, got ${JSON.stringify(configured)}`,
			);
		}
		token = configured;
	} else if (fromEnv !== undefined && fromEnv.length > 0) {
		token = fromEnv;
	}
	// cedar-agent compares the header to its `--authentication` value verbatim: no scheme.
	if (token !== undefined) headers.authorization = token;
	return headers;
}

// --- the wire ------------------------------------------------------------------

async function send(doFetch: typeof fetch, url: string, init: RequestInit): Promise<Response> {
	try {
		return await doFetch(url, init);
	} catch (cause) {
		// The rule's signal aborting is the caller's or the deadline's doing; the
		// evaluator maps that itself. Everything else is the engine not answering.
		if (init.signal?.aborted) throw init.signal.reason;
		throw new CedarEngineError(`cedar engine at ${url} is unreachable: ${errorMessage(cause)}`);
	}
}

/** cedar-agent's error body is `{ reason, description, code }`; fall back to the status text. */
async function errorDescription(response: Response): Promise<string> {
	const body: unknown = await response.json().catch(() => undefined);
	if (typeof body === "object" && body !== null) {
		const description = (body as Record<string, unknown>).description;
		if (typeof description === "string" && description.length > 0) return description;
	}
	return response.statusText || "no description";
}

/** Reads cedar-agent's `AuthorizationAnswer`; anything else is the engine not answering. */
function readDecision(body: unknown, endpoint: string): CedarDecision {
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
	const reason = stringList((diagnostics as Record<string, unknown> | undefined)?.reason);
	const errors = stringList((diagnostics as Record<string, unknown> | undefined)?.errors);
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
	return { decision: normalized, reason, errors };
}

function stringList(value: unknown): string[] | undefined {
	if (!Array.isArray(value) || !value.every((item): item is string => typeof item === "string")) {
		return undefined;
	}
	return value;
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

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
