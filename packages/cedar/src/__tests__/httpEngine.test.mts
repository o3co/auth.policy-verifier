// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The HTTP engine against a scripted `fetch`: what it sends cedar-agent, what
 * it makes of the answers, and how it fails. The wire shape is cedar-agent's
 * (`PUT /v1/policies` with `[{ id, content }]`, `POST /v1/is_authorized` with
 * entity references as `Type::"id"` literals and a `{ decision, diagnostics }`
 * answer) — pinned here so a change on either side shows up as a test.
 */

import type { Logger, RuleEvaluation } from "@o3co/auth.policy-verifier.core";
import { evaluate, isAsyncRule } from "@o3co/auth.policy-verifier.core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CedarPolicyRuleCollector } from "../CedarPolicyRuleCollector.mjs";
import { CedarEngineError, type CedarEngineLoadContext } from "../engine.mjs";
import {
	CEDAR_ANSWER_MAX_BYTES,
	CEDAR_AUTHENTICATION_ENV,
	CEDAR_ENDPOINT_ENV,
	createCedarHttpEngine,
	entityUidLiteral,
} from "../httpEngine.mjs";
import type { CedarRequest } from "../mapping.mjs";
import { computePolicyRevision, type PolicySource } from "../policySource.mjs";
// Registers the http engine under "http" for the collector-level cases.
import "../index.mjs";

const PERMIT_ALL = "permit(principal, action, resource);";

/** The agent the tests point at — through the environment, as the template's compose file does. */
const AGENT = "http://127.0.0.1:8180";
const AGENT_ENV = { [CEDAR_ENDPOINT_ENV]: AGENT };

function silentLogger(): Logger {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: (): Logger => logger,
	} as Logger;
	return logger;
}

function loadContext(config: Record<string, unknown> = {}): CedarEngineLoadContext {
	return { config, logger: silentLogger() };
}

function inline(text: string): PolicySource {
	const files = [{ name: "policies", source: "policies (inline)", text }];
	return { files, text, description: "inline policies", revision: computePolicyRevision(files) };
}

function dir(entries: Array<[string, string]>): PolicySource {
	const files = entries.map(([name, text]) => ({
		name,
		source: `/etc/verifier/policies/${name}`,
		text,
	}));
	return {
		files,
		text: files.map((file) => file.text).join("\n"),
		description: "/etc/verifier/policies",
		revision: computePolicyRevision(files),
	};
}

function json(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

/** An error as Node's network stack makes one: a message and a `code`. */
function failure(message: string, code: string): Error & { code: string } {
	return Object.assign(new Error(message), { code });
}

/** What the real `fetch` rejects with when the agent's port is closed. */
function refused(): TypeError {
	return new TypeError("fetch failed", {
		cause: failure("connect ECONNREFUSED 127.0.0.1:8180", "ECONNREFUSED"),
	});
}

/** A fetch call that never answers, rejecting as the real `fetch` does once its signal aborts. */
function untilAborted(init: RequestInit | undefined): Promise<never> {
	return new Promise((_resolve, reject) => {
		const signal = init?.signal;
		if (!signal) return;
		signal.addEventListener("abort", () => reject(signal.reason), { once: true });
	});
}

/**
 * An answer whose status and first bytes have arrived and whose body then
 * stalls, until `fail` errors it — a body read in progress, without a network.
 */
function stalledBody(status: number, head: string, statusText?: string) {
	let body!: ReadableStreamDefaultController<Uint8Array>;
	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			body = controller;
			controller.enqueue(new TextEncoder().encode(head));
		},
	});
	return {
		response: new Response(stream, {
			status,
			statusText,
			headers: { "content-type": "application/json" },
		}),
		fail: (error: unknown) => body.error(error),
	};
}

const ALLOW = { decision: "Allow", diagnostics: { reason: ["policies"], errors: [] } };

/** A fetch that answers the policy push with 200 and every authorization call from `answer`. */
function agent(answer: (call: Record<string, unknown>) => Response = () => json(200, ALLOW)) {
	const calls: Array<{ url: string; init: RequestInit }> = [];
	const doFetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
		const url = String(input);
		calls.push({ url, init: init ?? {} });
		if (url.endsWith("/v1/policies")) return json(200, JSON.parse(String(init?.body)));
		return answer(JSON.parse(String(init?.body)));
	}) as unknown as typeof fetch;
	return { doFetch, calls };
}

const NEVER_ABORTS = new AbortController().signal;

/** The answer bound, written out so a test's sizes do not depend on the constant under test. */
const MIB = 1024 * 1024;

/** A valid Allow whose determining-policy list alone is `policies` ids long. */
function largeAllow(policies: number): string {
	const reason = Array.from(
		{ length: policies },
		(_, i) => `policy-${String(i).padStart(6, "0")}-permit-read`,
	);
	return JSON.stringify({ decision: "Allow", diagnostics: { reason, errors: [] } });
}

function request(): CedarRequest {
	const principal = { type: "User", id: "alice" };
	const resource = { type: "Document", id: "42" };
	return {
		principal,
		action: { type: "Action", id: "read" },
		resource,
		context: { mfa: true },
		entities: [
			{ uid: principal, attrs: { dept: "eng" }, parents: [{ type: "Group", id: "admins" }] },
			{ uid: resource, attrs: { owner: { __entity: principal } }, parents: [] },
		],
	};
}

async function loadAsync(
	engine: ReturnType<typeof createCedarHttpEngine>,
	source: PolicySource,
	config?: Record<string, unknown>,
) {
	const loaded = await engine.load(source, loadContext(config));
	if (!loaded.async) throw new Error("the http engine answers asynchronously");
	return loaded;
}

function headersOf(call: { init: RequestInit }): Record<string, string> {
	return call.init.headers as Record<string, string>;
}

describe("cedarHttpEngine — load pushes the policy set", () => {
	it("PUTs one entry per file, named after the file, to the default endpoint", async () => {
		const { doFetch, calls } = agent();
		const engine = createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV });
		const forbid = "forbid(principal, action, resource) when { context.suspended == true };";
		await loadAsync(
			engine,
			dir([
				["10-permit.cedar", PERMIT_ALL],
				["20-forbid.cedar", forbid],
			]),
		);
		expect(calls).toHaveLength(1);
		expect(calls[0].url).toBe(`${AGENT}/v1/policies`);
		expect(calls[0].init.method).toBe("PUT");
		expect(JSON.parse(String(calls[0].init.body))).toEqual([
			{ id: "10-permit", content: PERMIT_ALL },
			{ id: "20-forbid", content: forbid },
		]);
		expect(headersOf(calls[0])["content-type"]).toBe("application/json");
		expect(headersOf(calls[0]).authorization).toBeUndefined();
	});

	it("names inline policies `policies` and skips blank files — the empty set is migration step one", async () => {
		const { doFetch, calls } = agent();
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }), inline(PERMIT_ALL));
		expect(JSON.parse(String(calls[0].init.body))).toEqual([
			{ id: "policies", content: PERMIT_ALL },
		]);

		await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
			dir([["blank.cedar", "  \n"]]),
		);
		expect(JSON.parse(String(calls[1].init.body))).toEqual([]);
	});

	it("refuses a file whose name yields an empty policy id, before sending anything", async () => {
		const { doFetch, calls } = agent();
		const engine = createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV });
		await expect(engine.load(dir([[".cedar", PERMIT_ALL]]), loadContext())).rejects.toThrow(
			/"\/etc\/verifier\/policies\/\.cedar" yields an empty policy id/,
		);
		expect(calls).toHaveLength(0);
		// The endpoint was released: a proper set loads afterwards.
		await loadAsync(engine, inline(PERMIT_ALL));
	});

	it("sends the agent's authorization token verbatim: config over environment", async () => {
		const { doFetch, calls } = agent();
		const env = { ...AGENT_ENV, [CEDAR_AUTHENTICATION_ENV]: "from-env" };
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env }), inline(PERMIT_ALL));
		expect(headersOf(calls[0]).authorization).toBe("from-env");

		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env }), inline(PERMIT_ALL), {
			authentication: "from-config",
		});
		expect(headersOf(calls[1]).authorization).toBe("from-config");
	});

	it("names the token when the agent refuses the load as unauthenticated (v0.10.0 audit)", async () => {
		// The template's agent is started with CEDAR_AGENT_AUTHENTICATION from
		// CEDAR_AUTHENTICATION, so a deployment that forgot to set it gets a 401.
		// The agent's own 401 body says nothing about which variable to set.
		const unauthorized = vi.fn(async () =>
			json(401, {
				reason: "Unauthorized",
				description: "The request requires user authentication.",
				code: 401,
			}),
		) as unknown as typeof fetch;
		await expect(
			createCedarHttpEngine({ fetch: unauthorized, env: AGENT_ENV }).load(
				inline(PERMIT_ALL),
				loadContext(),
			),
		).rejects.toThrow(
			/requires a token and none was sent — set authentication \(or CEDAR_AUTHENTICATION\) to the token the agent was started with/,
		);
		await expect(
			createCedarHttpEngine({
				fetch: unauthorized,
				env: { ...AGENT_ENV, [CEDAR_AUTHENTICATION_ENV]: "wrong" },
			}).load(inline(PERMIT_ALL), loadContext()),
		).rejects.toThrow(/did not accept the token from CEDAR_AUTHENTICATION/);
	});

	it("refuses to start when the agent refuses the set, in the agent's words", async () => {
		const doFetch = vi.fn(async () =>
			json(400, {
				reason: "You have malformed a bad request",
				description:
					"The content in the request does not match the specifications: policy 20-forbid: unexpected token",
				code: 400,
			}),
		) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV });
		await expect(
			engine.load(dir([["20-forbid.cedar", "forbid(when;"]]), loadContext()),
		).rejects.toThrow(
			/refused the policy set from \/etc\/verifier\/policies \(400; policies: 20-forbid\): .*policy 20-forbid: unexpected token/,
		);
	});

	it("reads a refusing agent's error body at load up to maxAnswerBytes too", async () => {
		const doFetch = vi.fn(
			async () =>
				new Response(`{"description":"${"x".repeat(2048)}"}`, {
					status: 400,
					statusText: "Bad Request",
				}),
		) as unknown as typeof fetch;
		await expect(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }).load(
				inline(PERMIT_ALL),
				loadContext({ maxAnswerBytes: 1024 }),
			),
		).rejects.toThrow(
			/refused the policy set from inline policies \(400; policies: policies\): Bad Request$/,
		);
	});

	it("retries an unreachable agent until the load deadline, then refuses to start naming it and the cause", async () => {
		let attempts = 0;
		const doFetch = vi.fn(async () => {
			attempts++;
			throw refused();
		}) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({
			fetch: doFetch,
			env: AGENT_ENV,
			loadTimeoutMs: 40,
			retryMs: 10,
		});
		await expect(engine.load(inline(PERMIT_ALL), loadContext())).rejects.toThrow(
			new RegExp(
				`cedar engine at ${AGENT} is unreachable — could not load .* within 40 ms \\(\\d+ attempts\\): fetch failed: connect ECONNREFUSED 127\\.0\\.0\\.1:8180$`,
			),
		);
		expect(attempts).toBeGreaterThan(1);
	});

	it("says no answer came in time when the load deadline passes on the first attempt — not that the agent is reachable (#271)", async () => {
		// A timeout proves only that nothing answered: a host that drops packets
		// never completes the connection, and times out the same way.
		let attempts = 0;
		const doFetch = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			attempts++;
			return untilAborted(init);
		}) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({
			fetch: doFetch,
			env: AGENT_ENV,
			loadTimeoutMs: 40,
			retryMs: 10,
		});
		const load = engine.load(inline(PERMIT_ALL), loadContext());
		await expect(load).rejects.toThrow(
			/did not accept the policy set from inline policies within 40 ms \(1 attempts\) — the request got no response before the deadline: the agent took it and did not answer, or the connection never completed$/,
		);
		await expect(load).rejects.not.toThrow(/\breachable\b/);
		expect(attempts).toBe(1);
	});

	it("names the refusal before it when the deadline lands on a later attempt, and does not call the agent reachable (#271)", async () => {
		// The retry after a refusal runs on what is left of the deadline — a
		// millisecond, when a timer overshoots — and can time out before its own
		// refusal arrives. Scripted: refused, then no answer until the deadline.
		let attempts = 0;
		const doFetch = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			attempts++;
			if (attempts === 1) throw refused();
			return untilAborted(init);
		}) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({
			fetch: doFetch,
			env: AGENT_ENV,
			loadTimeoutMs: 40,
			retryMs: 10,
		});
		const load = engine.load(inline(PERMIT_ALL), loadContext());
		await expect(load).rejects.toThrow(
			/did not accept the policy set from inline policies within 40 ms \(2 attempts\) — the last got no response before the deadline, and the one before it failed: fetch failed: connect ECONNREFUSED 127\.0\.0\.1:8180$/,
		);
		await expect(load).rejects.not.toThrow(/\breachable\b/);
		expect(attempts).toBe(2);
	});

	it("tells the deadline by its own signal, not by the name of what the fetch threw", async () => {
		// A TimeoutError from a fetch whose deadline has not passed is a failure
		// like any other — retried, and named when the retries run out.
		let attempts = 0;
		const doFetch = vi.fn(async () => {
			attempts++;
			throw new DOMException("the dispatcher's own connect timeout", "TimeoutError");
		}) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({
			fetch: doFetch,
			env: AGENT_ENV,
			loadTimeoutMs: 40,
			retryMs: 10,
		});
		await expect(engine.load(inline(PERMIT_ALL), loadContext())).rejects.toThrow(
			/is unreachable — could not load .* within 40 ms \(\d+ attempts\): the dispatcher's own connect timeout$/,
		);
		expect(attempts).toBeGreaterThan(1);
	});

	it("comes up when the agent does — a compose sibling a few hundred milliseconds behind", async () => {
		let attempts = 0;
		const { doFetch } = agent();
		const flaky = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			attempts++;
			if (attempts < 3) throw refused();
			return doFetch(input, init);
		}) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({
			fetch: flaky,
			env: AGENT_ENV,
			loadTimeoutMs: 500,
			retryMs: 5,
		});
		await loadAsync(engine, inline(PERMIT_ALL));
		expect(attempts).toBe(3);
	});

	it("runs one policy set per agent — a second load against the same endpoint is refused", async () => {
		const { doFetch } = agent();
		const engine = createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV });
		await loadAsync(engine, inline(PERMIT_ALL));
		await expect(engine.load(dir([["other.cedar", PERMIT_ALL]]), loadContext())).rejects.toThrow(
			/already holds the policy set from inline policies — PUT \/v1\/policies replaces an agent's whole set/,
		);
	});

	it("treats two spellings of one loopback agent as the same agent (v0.10.0 audit)", async () => {
		// The guard was keyed on the endpoint string, so `127.0.0.1` and
		// `localhost` were two keys for one agent, and the second collector
		// replaced the first's policy set — the outcome the guard exists to stop.
		const { doFetch } = agent();
		const engine = createCedarHttpEngine({ fetch: doFetch, env: {} });
		await loadAsync(engine, inline(PERMIT_ALL), { endpoint: "http://127.0.0.1:8180" });
		for (const endpoint of [
			"http://localhost:8180",
			"http://[::1]:8180/",
			"http://127.0.0.2:8180",
		]) {
			await expect(
				engine.load(dir([["other.cedar", PERMIT_ALL]]), loadContext({ endpoint })),
				endpoint,
			).rejects.toThrow(/already holds the policy set from inline policies/);
		}
		// A different port is a different agent.
		await expect(
			loadAsync(engine, dir([["other.cedar", PERMIT_ALL]]), { endpoint: "http://127.0.0.1:8181" }),
		).resolves.toBeDefined();
	});

	it("refuses the second of two concurrent loads too, and frees the endpoint when a load fails", async () => {
		const { doFetch } = agent();
		const engine = createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV });
		const results = await Promise.allSettled([
			engine.load(inline(PERMIT_ALL), loadContext()),
			engine.load(dir([["other.cedar", PERMIT_ALL]]), loadContext()),
		]);
		expect(results.map((result) => result.status)).toEqual(["fulfilled", "rejected"]);

		const refusing = vi.fn(async () => json(400, { description: "no" })) as unknown as typeof fetch;
		const failing = createCedarHttpEngine({
			fetch: refusing,
			env: AGENT_ENV,
			loadTimeoutMs: 40,
			retryMs: 10,
		});
		await expect(failing.load(inline(PERMIT_ALL), loadContext())).rejects.toThrow(/refused/);
		// The failed load did not leave the endpoint marked as held.
		await expect(failing.load(inline(PERMIT_ALL), loadContext())).rejects.toThrow(/refused/);
	});
});

describe("cedarHttpEngine — where the agent is", () => {
	it("prefers the config endpoint, then CEDAR_ENDPOINT", async () => {
		const { doFetch, calls } = agent();
		const env = { [CEDAR_ENDPOINT_ENV]: "http://localhost:9001" };
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env }), inline(PERMIT_ALL), {
			endpoint: "http://127.0.0.1:9002/cedar/",
		});
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env }), inline(PERMIT_ALL));
		expect(calls.map((call) => call.url)).toEqual([
			"http://127.0.0.1:9002/cedar/v1/policies",
			"http://localhost:9001/v1/policies",
		]);
	});

	it("refuses to start with no endpoint at all, naming both ways out, before any request (v0.10.0 audit)", async () => {
		// A v0.9.0 deployment that upgrades without the wasm package is resolved
		// to this engine. With a loopback default it spent ten seconds on
		// "cedar engine at http://127.0.0.1:8180 is unreachable", which names
		// neither the cause nor the fix — or, if something answered there, booted
		// against an evaluator nobody chose. #225 specified a config error.
		const { doFetch, calls } = agent();
		await expect(
			createCedarHttpEngine({ fetch: doFetch, env: {} }).load(inline(PERMIT_ALL), loadContext()),
		).rejects.toThrow(
			/no cedar engine endpoint is configured — set endpoint \(or CEDAR_ENDPOINT\) to run against a cedar-agent, or import "@o3co\/auth\.policy-verifier\.cedar-wasm" to evaluate in-process/,
		);
		expect(calls).toHaveLength(0);
	});

	it("accepts https to any host and plain http to loopback only", async () => {
		const { doFetch, calls } = agent();
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }), inline(PERMIT_ALL), {
			endpoint: "https://cedar.internal:8443",
		});
		// Every loopback spelling: IPv6 (`URL.hostname` keeps its brackets), the
		// name, and the whole 127.0.0.0/8 block — the server's own loopback rule.
		const loopbacks = [
			"http://[::1]:8180",
			"http://localhost:8180",
			"http://127.0.0.1:8180",
			"http://127.0.0.2:8180",
			"http://127.255.255.254:8180",
		];
		for (const endpoint of loopbacks) {
			await loadAsync(
				createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
				inline(PERMIT_ALL),
				{
					endpoint,
				},
			);
		}
		expect(calls.at(-5)?.url).toBe("http://[::1]:8180/v1/policies");
		// Look-alikes are routable names and stay refused.
		for (const endpoint of ["http://127.0.0.1.attacker.test", "http://localhost.attacker.test"]) {
			await expect(
				createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }).load(
					inline(PERMIT_ALL),
					loadContext({ endpoint }),
				),
			).rejects.toThrow(/plain http to a routable host/);
		}
		await expect(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }).load(
				inline(PERMIT_ALL),
				loadContext({ endpoint: "http://cedar.internal:8180" }),
			),
		).rejects.toThrow(
			/plain http to a routable host \(cedar\.internal\).*use https, or a loopback address/,
		);
	});

	it("refuses an endpoint that is not a base http(s) URL", async () => {
		const { doFetch } = agent();
		const load = (config: Record<string, unknown>, env: Record<string, string> = {}) =>
			createCedarHttpEngine({ fetch: doFetch, env }).load(inline(PERMIT_ALL), loadContext(config));
		await expect(load({ endpoint: 7 })).rejects.toThrow(
			/endpoint must be a non-empty URL string, got 7/,
		);
		await expect(load({ endpoint: "not a url" })).rejects.toThrow(/config endpoint is not a URL/);
		await expect(load({ endpoint: "ftp://127.0.0.1" })).rejects.toThrow(/must be an http\(s\) URL/);
		await expect(load({ endpoint: "http://127.0.0.1:8180/?x=1" })).rejects.toThrow(
			/without query or fragment/,
		);
		await expect(load({}, { [CEDAR_ENDPOINT_ENV]: "nope" })).rejects.toThrow(
			/CEDAR_ENDPOINT is not a URL/,
		);
		// `url.origin` would drop these silently; the token goes in the header.
		await expect(load({ endpoint: "https://user:secret@cedar.internal:8443" })).rejects.toThrow(
			/must not carry credentials in the URL — set authentication \(or CEDAR_AUTHENTICATION\)/,
		);
	});

	it("refuses a malformed authentication value", async () => {
		const { doFetch } = agent();
		await expect(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }).load(
				inline(PERMIT_ALL),
				loadContext({ authentication: 7 }),
			),
		).rejects.toThrow(/authentication must be a non-empty string/);
	});

	// `fetch` refuses a header value that holds an ASCII control character other
	// than a tab once the whitespace around it is trimmed, or a character
	// above U+00FF. For a line break or a NUL its error quotes the whole
	// value, which the load then logged on every retry; for the others it
	// does not. Either way the load called the agent unreachable and retried
	// for ten seconds (#271). Refused at load instead, naming where the token
	// came from, never the token.
	it.each([
		["a line break inside", "s3cr3t-1\ns3cr3t-2"],
		["a header smuggled after CRLF", "s3cr3t\r\nX-Other: y"],
		["a NUL", "s3c\u0000r3t"],
		["a DEL", "s3cr\u007ft"],
		["a form feed after it, which is not trimmed", "s3cr3t\u000c"],
		["a vertical tab inside", "s3c\u000br3t"],
		["a character above U+00FF", "s3cr€t"],
	])(
		"refuses a token fetch cannot send — %s — without repeating it (#271)",
		async (_label, token) => {
			const { doFetch, calls } = agent();
			for (const [config, env, source] of [
				[{ authentication: token }, AGENT_ENV, "authentication"],
				[{}, { ...AGENT_ENV, [CEDAR_AUTHENTICATION_ENV]: token }, CEDAR_AUTHENTICATION_ENV],
			] as const) {
				let message = "";
				try {
					await createCedarHttpEngine({ fetch: doFetch, env }).load(
						inline(PERMIT_ALL),
						loadContext(config),
					);
				} catch (error) {
					expect(error).toBeInstanceOf(CedarEngineError);
					message = (error as CedarEngineError).message;
				}
				expect(message).toMatch(
					new RegExp(
						`^${source} is not a valid HTTP header value — it holds an ASCII control character other than a tab, or a character above U\\+00FF`,
					),
				);
				expect(message).not.toContain(token);
				expect(message).not.toContain(token.slice(0, 4));
			}
			expect(calls).toEqual([]);
		},
	);

	it("still sends a tab or a Latin-1 character inside a token, as fetch does", async () => {
		const { doFetch, calls } = agent();
		await loadAsync(
			createCedarHttpEngine({
				fetch: doFetch,
				env: { ...AGENT_ENV, [CEDAR_AUTHENTICATION_ENV]: "s3c\tr\u00e9t" },
			}),
			inline(PERMIT_ALL),
		);
		expect(headersOf(calls[0]).authorization).toBe("s3c\tr\u00e9t");
	});

	it("still sends a token whose only whitespace is around it, as fetch trims it", async () => {
		const { doFetch, calls } = agent();
		await loadAsync(
			createCedarHttpEngine({
				fetch: doFetch,
				env: { ...AGENT_ENV, [CEDAR_AUTHENTICATION_ENV]: "token\n" },
			}),
			inline(PERMIT_ALL),
		);
		expect(headersOf(calls[0]).authorization).toBe("token\n");
	});
});

describe("cedarHttpEngine — isAuthorized", () => {
	it("POSTs cedar-agent's AuthorizationCall: entity references as literals, entities inline, the rule's signal", async () => {
		const { doFetch, calls } = agent();
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		const controller = new AbortController();
		const answer = await loaded.isAuthorized(request(), controller.signal);
		expect(answer).toEqual({ decision: "allow", reason: ["policies"], errors: [] });

		const call = calls[1];
		expect(call.url).toBe(`${AGENT}/v1/is_authorized`);
		expect(call.init.method).toBe("POST");
		expect(call.init.signal).toBe(controller.signal);
		expect(JSON.parse(String(call.init.body))).toEqual({
			principal: 'User::"alice"',
			action: 'Action::"read"',
			resource: 'Document::"42"',
			context: { mfa: true },
			entities: request().entities,
		});
	});

	it("reads Deny with the determining policies and the agent's error strings", async () => {
		const { doFetch } = agent(() =>
			json(200, {
				decision: "Deny",
				diagnostics: {
					reason: ["20-forbid"],
					errors: ["policy 10-permit: attribute dept missing"],
				},
			}),
		);
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		expect(await loaded.isAuthorized(request(), NEVER_ABORTS)).toEqual({
			decision: "deny",
			reason: ["20-forbid"],
			errors: ["policy 10-permit: attribute dept missing"],
		});
	});

	it("reads structured diagnostics as rendered text rather than refusing the answer (v0.10.0 audit)", async () => {
		// cedar-agent 0.2.x rides cedar-policy 2.4, which reports errors as
		// strings; Cedar 3.x+ serialises them as objects. Refusing every
		// non-string turned an agent image bump into every request denied, with
		// a message about "well-formed diagnostics". The rule only logs errors and
		// decides on whether there are any, so the text is enough.
		const structured = { policyId: "20-forbid", error: { message: "attribute `dept` missing" } };
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent(() =>
					json(200, {
						decision: "Allow",
						diagnostics: { reason: [{ policyId: "10-permit" }], errors: [structured] },
					}),
				).doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
		);
		const answer = await loaded.isAuthorized(request(), NEVER_ABORTS);
		expect(answer.decision).toBe("allow");
		expect(answer.errors).toEqual([JSON.stringify(structured)]);
		expect(answer.reason).toEqual([JSON.stringify({ policyId: "10-permit" })]);
	});

	it("rejects with CedarEngineError when the agent answers non-2xx, not JSON, or not a decision", async () => {
		const cases: Array<[() => Response, RegExp]> = [
			[
				() => json(400, { description: "while parsing context, found a `null`" }),
				/answered 400 to an authorization call: while parsing context/,
			],
			[() => new Response("<html>", { status: 200 }), /not a decision/],
			[
				() => json(200, { decision: "Maybe", diagnostics: { reason: [], errors: [] } }),
				/unknown decision "Maybe"/,
			],
			[
				() => json(200, { decision: "Allow", diagnostics: { reason: "policies", errors: [] } }),
				/without well-formed diagnostics/,
			],
			// Missing lists are not "no reasons, no errors": that is some other
			// shape, and inferring "no errors" from an absent field would be the
			// fail-open reading of an answer the engine did not give.
			[() => json(200, { decision: "Allow" }), /without well-formed diagnostics/],
			[
				() => json(200, { decision: "Allow", diagnostics: { reason: [] } }),
				/without well-formed diagnostics/,
			],
		];
		for (const [response, expected] of cases) {
			const loaded = await loadAsync(
				createCedarHttpEngine({ fetch: agent(response).doFetch, env: AGENT_ENV }),
				inline(PERMIT_ALL),
			);
			const failure = loaded.isAuthorized(request(), NEVER_ABORTS);
			await expect(failure).rejects.toThrow(CedarEngineError);
			await expect(failure).rejects.toThrow(expected);
		}
	});

	it("rejects with CedarEngineError when the agent is unreachable, and with the signal's reason when aborted", async () => {
		const { doFetch } = agent(() => {
			throw new TypeError("fetch failed", { cause: failure("read ECONNRESET", "ECONNRESET") });
		});
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		await expect(loaded.isAuthorized(request(), NEVER_ABORTS)).rejects.toThrow(
			/cedar engine at .*\/v1\/is_authorized is unreachable: fetch failed: read ECONNRESET$/,
		);

		const reason = new Error("deadline");
		const aborting = agent(() => {
			throw new DOMException("The operation was aborted", "AbortError");
		});
		const set = await loadAsync(
			createCedarHttpEngine({ fetch: aborting.doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		const controller = new AbortController();
		controller.abort(reason);
		await expect(set.isAuthorized(request(), controller.signal)).rejects.toBe(reason);
	});

	// The real `fetch` rejects with "fetch failed" whatever happened; what did
	// happen is on `cause` (#271). The shapes below are the ones undici gives.
	const transportFailures: Array<[string, unknown, RegExp]> = [
		[
			"a refusal, whose message carries its code",
			new TypeError("fetch failed", {
				cause: failure("connect ECONNREFUSED 127.0.0.1:8180", "ECONNREFUSED"),
			}),
			/is unreachable: fetch failed: connect ECONNREFUSED 127\.0\.0\.1:8180$/,
		],
		[
			"a reset, whose code is only on the error",
			new TypeError("fetch failed", { cause: failure("other side closed", "UND_ERR_SOCKET") }),
			/is unreachable: fetch failed: UND_ERR_SOCKET: other side closed$/,
		],
		[
			"a refusal per address tried, as localhost gives",
			new TypeError("fetch failed", {
				cause: Object.assign(
					new AggregateError(
						[
							failure("connect ECONNREFUSED ::1:8180", "ECONNREFUSED"),
							failure("connect ECONNREFUSED 127.0.0.1:8180", "ECONNREFUSED"),
						],
						"",
					),
					{ code: "ECONNREFUSED" },
				),
			}),
			/is unreachable: fetch failed: connect ECONNREFUSED ::1:8180; connect ECONNREFUSED 127\.0\.0\.1:8180$/,
		],
		[
			"a name that does not resolve",
			new TypeError("fetch failed", {
				cause: failure("getaddrinfo ENOTFOUND agent.internal", "ENOTFOUND"),
			}),
			/is unreachable: fetch failed: getaddrinfo ENOTFOUND agent\.internal$/,
		],
		[
			"a TLS failure, whose OpenSSL message spans lines",
			new TypeError("fetch failed", {
				cause: failure(
					"809D55EF01000000:error:0A00010B:SSL routines:tls_validate_record_header:wrong version number:ssl/record/methods/tlsany_meth.c:78:\n",
					"ERR_SSL_WRONG_VERSION_NUMBER",
				),
			}),
			/is unreachable: fetch failed: ERR_SSL_WRONG_VERSION_NUMBER: 809D55EF01000000:error:0A00010B:SSL routines:tls_validate_record_header:wrong version number:ssl\/record\/methods\/tlsany_meth\.c:78:$/,
		],
		[
			"a failure with no cause — a fetch of the deployment's own",
			new TypeError("fetch failed"),
			/is unreachable: fetch failed$/,
		],
	];

	it.each(transportFailures)(
		"names the transport failure: %s (#271)",
		async (_label, thrown, expected) => {
			const { doFetch } = agent(() => {
				throw thrown;
			});
			const loaded = await loadAsync(
				createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
				inline(PERMIT_ALL),
			);
			const rejected = loaded.isAuthorized(request(), NEVER_ABORTS);
			await expect(rejected).rejects.toThrow(CedarEngineError);
			await expect(rejected).rejects.toThrow(expected);
		},
	);

	it("bounds what a cause adds: each link cut short, a cycle followed once (#271)", async () => {
		const looping = failure("x".repeat(1000), "ELOOP_TEST");
		looping.cause = looping;
		const { doFetch } = agent(() => {
			throw new TypeError("fetch failed", { cause: looping });
		});
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		const message = await loaded.isAuthorized(request(), NEVER_ABORTS).then(
			() => "",
			(error: Error) => error.message,
		);
		const cause = message.slice(message.indexOf("fetch failed: ") + "fetch failed: ".length);
		expect(cause).toMatch(/^ELOOP_TEST: x+…$/);
		expect(cause.length).toBe(200);
	});

	it("follows a cause chain four links deep, no further", async () => {
		const chain = ["one", "two", "three", "four", "five", "six"].reduceRight<Error | undefined>(
			(cause, message) => new Error(message, { cause }),
			undefined,
		);
		const { doFetch } = agent(() => {
			throw chain;
		});
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		await expect(loaded.isAuthorized(request(), NEVER_ABORTS)).rejects.toThrow(
			/is unreachable: one: two: three: four$/,
		);
	});

	// Whatever a `fetch` rejects with, describing it must not throw: a throw
	// there escaped as something other than a CedarEngineError, and at load
	// it skipped the retry loop.
	it.each([
		[
			"an AggregateError that holds itself",
			() => {
				const aggregate = new AggregateError([], "");
				aggregate.errors.push(aggregate, failure("connect ECONNREFUSED ::1:8180", "ECONNREFUSED"));
				return new TypeError("fetch failed", { cause: aggregate });
			},
			/is unreachable: fetch failed: connect ECONNREFUSED ::1:8180$/,
		],
		[
			"a cause with no prototype, so no toString",
			() => new TypeError("fetch failed", { cause: Object.create(null) }),
			/is unreachable: fetch failed: a failure that could not be described$/,
		],
		[
			// Only a custom `fetch` could hand over either of these two.
			"a cause getter that never runs out",
			() => {
				const endless = (): Error => {
					const link = new Error("");
					Object.defineProperty(link, "cause", { get: endless });
					return link;
				};
				return new TypeError("fetch failed", { cause: endless() });
			},
			/is unreachable: fetch failed$/,
		],
		[
			"an AggregateError whose errors never run out",
			() => {
				const aggregate = new AggregateError([], "");
				Object.defineProperty(aggregate.errors, Symbol.iterator, {
					*value() {
						for (;;) yield new Error("");
					},
				});
				return new TypeError("fetch failed", { cause: aggregate });
			},
			/is unreachable: fetch failed$/,
		],
		[
			"a message getter that throws",
			() => {
				const hostile = new Error("unused");
				Object.defineProperty(hostile, "message", {
					get() {
						throw new Error("no");
					},
				});
				return new TypeError("fetch failed", { cause: hostile });
			},
			/is unreachable: fetch failed: a failure that could not be described$/,
		],
	])("describes %s without throwing (#271)", async (_label, make, expected) => {
		const thrown = make();
		const { doFetch } = agent(() => {
			throw thrown;
		});
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		const rejected = loaded.isAuthorized(request(), NEVER_ABORTS);
		await expect(rejected).rejects.toThrow(CedarEngineError);
		await expect(rejected).rejects.toThrow(expected);
	});

	// The answer is read whole before it is parsed, so without a bound a
	// faulty agent — or a proxy in front of it — streaming a large body would
	// hold memory for the whole rule deadline, per concurrent call, and an
	// exhausted process takes every route down with it, not only the ones
	// Cedar gates (#271). Over the bound, the call fails closed.
	it("bounds an answer at 1 MiB by default (#271)", () => {
		expect(CEDAR_ANSWER_MAX_BYTES).toBe(MIB);
	});

	it("refuses an answer that declares more than CEDAR_ANSWER_MAX_BYTES, before reading it (#271)", async () => {
		let pulled = 0;
		const body = new ReadableStream<Uint8Array>({
			pull(controller) {
				pulled++;
				if (pulled > 1100) return controller.close();
				controller.enqueue(new Uint8Array(1024).fill(0x20));
			},
		});
		const response = new Response(body, {
			status: 200,
			headers: { "content-length": String(MIB + 1) },
		});
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: agent(() => response).doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		const rejected = loaded.isAuthorized(request(), NEVER_ABORTS);
		await expect(rejected).rejects.toThrow(CedarEngineError);
		await expect(rejected).rejects.toThrow(
			/cedar engine at http:\/\/127\.0\.0\.1:8180 answered an authorization call with more than 1 MiB — refused; set maxAnswerBytes higher if its answers are this large$/,
		);
		// The stream's first pull is the source filling its queue, not a read.
		expect(pulled).toBeLessThanOrEqual(1);
	});

	it("refuses an answer that streams past CEDAR_ANSWER_MAX_BYTES without declaring a length (#271)", async () => {
		// Four times the bound, then the end: finite, so an engine without the
		// bound reads it all and fails on the parse instead.
		let sent = 0;
		const body = new ReadableStream<Uint8Array>({
			pull(controller) {
				if (sent >= 4 * MIB) return controller.close();
				sent += 64 * 1024;
				controller.enqueue(new Uint8Array(64 * 1024).fill(0x20));
			},
		});
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent(() => new Response(body, { status: 200 })).doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
		);
		await expect(loaded.isAuthorized(request(), NEVER_ABORTS)).rejects.toThrow(
			/answered an authorization call with more than 1 MiB — refused; set maxAnswerBytes higher if its answers are this large$/,
		);
		expect(sent).toBeLessThanOrEqual(MIB + 2 * 64 * 1024);
	});

	it("reads an answer of exactly CEDAR_ANSWER_MAX_BYTES", async () => {
		const decision = JSON.stringify(ALLOW);
		const padded = decision + " ".repeat(MIB - decision.length);
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent(() => new Response(padded, { status: 200 })).doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
		);
		expect((await loaded.isAuthorized(request(), NEVER_ABORTS)).decision).toBe("allow");
	});

	it("keeps the status as the fact when an error's body is over the bound", async () => {
		const huge = `{"description":"${"x".repeat(MIB)}"}`;
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent(() => new Response(huge, { status: 500, statusText: "Internal Server Error" }))
					.doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
		);
		await expect(loaded.isAuthorized(request(), NEVER_ABORTS)).rejects.toThrow(
			/answered 500 to an authorization call: Internal Server Error$/,
		);
	});

	// A decision can be larger than the default bound and still be the
	// agent's honest answer: the determining-policy and error lists grow with
	// the policy set. Through 0.13.0 such an answer was read; under the default
	// it is refused, and `maxAnswerBytes` in the collector's config entry is the
	// way out. Found by the v0.14.0 release audit.
	it("refuses a valid decision larger than the default bound, saying how to raise it", async () => {
		const answer = largeAllow(40_000);
		expect(answer.length).toBeGreaterThan(MIB);
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent(() => new Response(answer, { status: 200 })).doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
		);
		await expect(loaded.isAuthorized(request(), NEVER_ABORTS)).rejects.toThrow(
			/answered an authorization call with more than 1 MiB — refused; set maxAnswerBytes higher if its answers are this large$/,
		);
	});

	it.each([
		["a number", 2 * MIB],
		// `maxAnswerBytes = ${?MY_ANSWER_BYTES}` in HOCON delivers a string,
		// as it does for the server's numeric knobs, and is read the same way.
		["the string a HOCON env substitution delivers", String(2 * MIB)],
	])("reads that decision when maxAnswerBytes allows it, written as %s", async (_label, bound) => {
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent(() => new Response(largeAllow(40_000), { status: 200 })).doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
			{ maxAnswerBytes: bound },
		);
		const answer = await loaded.isAuthorized(request(), NEVER_ABORTS);
		expect(answer.decision).toBe("allow");
		expect(answer.reason).toHaveLength(40_000);
	});

	// Each bound is met exactly and exceeded by one byte, once streamed and once
	// declared by content-length, so both checks are held at the boundary.
	it.each([
		[1024, "1 KiB", "streamed"],
		[1024, "1 KiB", "declared"],
		[1536, "1536 bytes", "streamed"],
		[1536, "1536 bytes", "declared"],
		[3 * MIB, "3 MiB", "streamed"],
	])("refuses above a maxAnswerBytes of %i, naming it as %s (%s)", async (bound, named, how) => {
		const decision = JSON.stringify(ALLOW);
		const bodies = {
			over: decision + " ".repeat(bound + 1 - decision.length),
			exact: decision + " ".repeat(bound - decision.length),
		};
		const answer = (text: string): Response =>
			how === "declared"
				? new Response(text, {
						status: 200,
						headers: { "content-length": String(Buffer.byteLength(text)) },
					})
				: new Response(text, { status: 200 });
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent((call) =>
					answer((call.principal as string).includes("over") ? bodies.over : bodies.exact),
				).doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
			{ maxAnswerBytes: bound },
		);
		const asking = (id: string): CedarRequest => ({
			...request(),
			principal: { type: "User", id },
		});
		expect((await loaded.isAuthorized(asking("exact"), NEVER_ABORTS)).decision).toBe("allow");
		await expect(loaded.isAuthorized(asking("over"), NEVER_ABORTS)).rejects.toThrow(
			new RegExp(`with more than ${named} — refused; set maxAnswerBytes higher`),
		);
	});

	it("reads an error's body up to maxAnswerBytes when that is below the default", async () => {
		const description = `{"description":"${"x".repeat(2048)}"}`;
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent(
					() => new Response(description, { status: 500, statusText: "Internal Server Error" }),
				).doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
			{ maxAnswerBytes: 1024 },
		);
		await expect(loaded.isAuthorized(request(), NEVER_ABORTS)).rejects.toThrow(
			/answered 500 to an authorization call: Internal Server Error$/,
		);
	});

	// A higher bound is for decisions. An error's body is the agent's
	// description of a failure, and becomes the log line, so it stays under
	// the default however high maxAnswerBytes is set.
	it("reads an error's body up to the default when maxAnswerBytes is above it", async () => {
		const description = `{"description":"${"x".repeat(2 * MIB)}"}`;
		const loaded = await loadAsync(
			createCedarHttpEngine({
				fetch: agent(
					() => new Response(description, { status: 500, statusText: "Internal Server Error" }),
				).doFetch,
				env: AGENT_ENV,
			}),
			inline(PERMIT_ALL),
			{ maxAnswerBytes: 8 * MIB },
		);
		await expect(loaded.isAuthorized(request(), NEVER_ABORTS)).rejects.toThrow(
			/answered 500 to an authorization call: Internal Server Error$/,
		);
	});

	it.each([
		["exactly 1 KiB", 1024],
		["exactly 256 MiB", 256 * MIB],
		["a string with spaces around it", " 2097152 "],
	])("accepts a maxAnswerBytes of %s", async (_label, value) => {
		const { doFetch } = agent();
		await expect(
			loadAsync(createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }), inline(PERMIT_ALL), {
				maxAnswerBytes: value,
			}),
		).resolves.toBeDefined();
	});

	it.each([
		["zero", 0, "0"],
		["negative", -1, "-1"],
		["fractional", 1.5, "1.5"],
		["NaN", Number.NaN, "NaN"],
		["Infinity", Number.POSITIVE_INFINITY, "Infinity"],
		["below 1 KiB — a unit slip that would deny every answer", 4, "4"],
		["above 256 MiB", 256 * MIB + 1, String(256 * MIB + 1)],
		["an integer too large to be safe", 1e300, "1e+300"],
		["a string that is not a number", "1 MiB", '"1 MiB"'],
		["a blank string", "  ", '"  "'],
		["null", null, "null"],
		["a boolean", true, "true"],
		["a bigint", BigInt(4194304), "4194304n"],
		["a symbol", Symbol("bytes"), "Symbol(bytes)"],
	])(
		"refuses a maxAnswerBytes that is %s at load, before anything is sent",
		async (_label, value, shown) => {
			const { doFetch, calls } = agent();
			await expect(
				createCedarHttpEngine({ fetch: doFetch, env: AGENT_ENV }).load(
					inline(PERMIT_ALL),
					loadContext({ maxAnswerBytes: value }),
				),
			).rejects.toThrow(
				new RegExp(
					`^maxAnswerBytes must be a whole number of bytes from 1 KiB to 256 MiB, got ${shown.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
				),
			);
			expect(calls).toEqual([]);
		},
	);

	// The status can arrive before the body does, and an abort can land in
	// between (#271): the body read then fails, and that is the signal's doing,
	// not the agent's. Here the body errors with a failure of its own, as a
	// `fetch` need not reject a body read with the signal's reason.
	it.each([
		["an answer", 200],
		["an error", 500],
	])(
		"rejects with the signal's reason when the deadline passes while %s's body is read (%i) (#271)",
		async (_label, status) => {
			const stalled = stalledBody(status, '{"decision":"Allow",');
			const loaded = await loadAsync(
				createCedarHttpEngine({ fetch: agent(() => stalled.response).doFetch, env: AGENT_ENV }),
				inline(PERMIT_ALL),
			);
			const controller = new AbortController();
			const reason = new Error("rule deadline");
			const rejected = loaded.isAuthorized(request(), controller.signal);
			rejected.catch(() => undefined);
			await new Promise((resolve) => setTimeout(resolve, 0));
			controller.abort(reason);
			stalled.fail(new TypeError("terminated"));
			await expect(rejected).rejects.toBe(reason);
		},
	);

	it("says the agent broke off its answer when the body stops without an abort, not that it answered garbage (#271)", async () => {
		const stalled = stalledBody(200, '{"decision":"Allow",');
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: agent(() => stalled.response).doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		const rejected = loaded.isAuthorized(request(), NEVER_ABORTS);
		rejected.catch(() => undefined);
		await new Promise((resolve) => setTimeout(resolve, 0));
		stalled.fail(
			new TypeError("terminated", { cause: failure("other side closed", "UND_ERR_SOCKET") }),
		);
		await expect(rejected).rejects.toThrow(CedarEngineError);
		await expect(rejected).rejects.toThrow(
			/cedar engine at http:\/\/127\.0\.0\.1:8180 broke off its answer to an authorization call: terminated: UND_ERR_SOCKET: other side closed$/,
		);
	});

	it("keeps the status as the fact when an error's body stops without an abort", async () => {
		const stalled = stalledBody(502, "<html>", "Bad Gateway");
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: agent(() => stalled.response).doFetch, env: AGENT_ENV }),
			inline(PERMIT_ALL),
		);
		const rejected = loaded.isAuthorized(request(), NEVER_ABORTS);
		rejected.catch(() => undefined);
		await new Promise((resolve) => setTimeout(resolve, 0));
		stalled.fail(new TypeError("terminated"));
		await expect(rejected).rejects.toThrow(CedarEngineError);
		await expect(rejected).rejects.toThrow(/answered 502 to an authorization call: Bad Gateway$/);
	});
});

describe("entityUidLiteral", () => {
	it("writes Cedar's own syntax, escaping the id as a string literal", () => {
		expect(entityUidLiteral({ type: "User", id: "alice" })).toBe('User::"alice"');
		expect(entityUidLiteral({ type: "App::User", id: 'a"b\\c' })).toBe('App::User::"a\\"b\\\\c"');
		expect(entityUidLiteral({ type: "User", id: "line\nbreak\ttab\0nul\x01soh" })).toBe(
			'User::"line\\nbreak\\ttab\\0nul\\u{1}soh"',
		);
	});

	it("refuses a type that is not a Cedar identifier path — it may come from an attribute", () => {
		for (const type of ["", "Doc ument", 'User"', "App::", "::User", "1st", 'User::"x"']) {
			expect(() => entityUidLiteral({ type, id: "x" })).toThrow(CedarEngineError);
			expect(() => entityUidLiteral({ type, id: "x" })).toThrow(/not a Cedar entity type path/);
		}
		expect(entityUidLiteral({ type: "_Ns1::Type_2", id: "x" })).toBe('_Ns1::Type_2::"x"');
	});
});

describe("CedarPolicyRuleCollector on the http engine", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	const context = {
		subject: { sub: "user-1" },
		resource: { raw: "document:42", resourceType: "document", resourceId: "42" },
		action: "read",
		signal: NEVER_ABORTS,
	};

	it("is selected by config, yields an AsyncRule, and decides through core evaluate", async () => {
		const { doFetch, calls } = agent();
		vi.stubGlobal("fetch", doFetch);
		const collector = await CedarPolicyRuleCollector.create(
			{
				engine: "http",
				endpoint: "http://127.0.0.1:18201",
				policies: PERMIT_ALL,
				principal: { attributes: { dept: "department" } },
			},
			{ logger: silentLogger() },
		);
		const [rule] = await collector.collect(context);
		expect(isAsyncRule(rule)).toBe(true);
		const attrs = new Map<string, unknown>([
			["userId", "alice"],
			["requestAction", "read"],
			["requestResourceType", "Document"],
			["requestResourceId", "42"],
			["department", "eng"],
		]);
		const decision = await evaluate(attrs, [rule]);
		expect(decision.decision).toBe("allow");
		expect(calls.at(-1)?.url).toBe("http://127.0.0.1:18201/v1/is_authorized");
		expect(JSON.parse(String(calls.at(-1)?.init.body)).principal).toBe('User::"alice"');
	});

	it("denies and logs on a resource type that is not an identifier path, without asking the agent", async () => {
		const { doFetch, calls } = agent();
		vi.stubGlobal("fetch", doFetch);
		const logger = silentLogger();
		const collector = await CedarPolicyRuleCollector.create(
			{ engine: "http", endpoint: "http://127.0.0.1:18204", policies: PERMIT_ALL },
			{ logger },
		);
		const [rule] = await collector.collect(context);
		if (!isAsyncRule(rule)) throw new Error("expected an AsyncRule");
		const before = calls.length;
		const attrs = new Map<string, unknown>([
			["userId", "alice"],
			["requestAction", "read"],
			["requestResourceType", 'Document"; forbid(principal, action, resource);'],
		]);
		expect(await rule.decide(attrs, NEVER_ABORTS)).toBe(false);
		expect(calls).toHaveLength(before);
		expect(JSON.stringify((logger.error as ReturnType<typeof vi.fn>).mock.calls[0])).toMatch(
			/not a Cedar entity type path/,
		);
	});

	it("leaves nothing behind when abstain is refused — the same process can start with deny (review)", async () => {
		const { doFetch, calls } = agent();
		vi.stubGlobal("fetch", doFetch);
		const config = { engine: "http", endpoint: "http://127.0.0.1:18299", policies: PERMIT_ALL };
		await expect(
			CedarPolicyRuleCollector.create({ ...config, onNoDeterminingPolicy: "abstain" }),
		).rejects.toThrow(/cannot be used with the asynchronous "http" engine/);
		// Nothing was pushed, and the agent is not held for the refused collector.
		expect(calls).toHaveLength(0);
		await expect(CedarPolicyRuleCollector.create(config)).resolves.toBeDefined();
	});

	it("reports what it pushed as loaded, never as evaluated — the agent does not say what it ran (#244)", async () => {
		// cedar-agent answers `{ decision, diagnostics }` and nothing else, and a
		// restarted agent comes back empty: the set pushed at boot is not proof
		// of the set that answered.
		let up = true;
		const { doFetch } = agent(() => {
			if (!up) throw refused();
			return json(200, ALLOW);
		});
		vi.stubGlobal("fetch", doFetch);
		const collector = await CedarPolicyRuleCollector.create(
			{ engine: "http", endpoint: "http://127.0.0.1:18205", policies: PERMIT_ALL },
			{ logger: silentLogger() },
		);
		const [rule] = await collector.collect(context);
		if (!isAsyncRule(rule)) throw new Error("expected an AsyncRule");
		const attrs = new Map<string, unknown>([
			["userId", "alice"],
			["requestAction", "read"],
			["requestResourceType", "Document"],
		]);
		const loadedRevision = inline(PERMIT_ALL).revision;
		// Asked the way core asks: the boolean back, the evaluation to a reporter.
		const ask = async () => {
			let evaluation: RuleEvaluation | undefined;
			const passed = await rule.decide(attrs, NEVER_ABORTS, (reported) => {
				evaluation = reported;
			});
			return { passed, evaluation };
		};
		expect(await ask()).toEqual({
			passed: true,
			evaluation: { status: "completed", revision: null, loadedRevision },
		});
		up = false;
		expect(await ask()).toEqual({
			passed: false,
			evaluation: { status: "failed", revision: null, loadedRevision },
		});
	});

	it("refuses requireConfirmedRevision at boot, before anything is pushed (#244)", async () => {
		const { doFetch, calls } = agent();
		vi.stubGlobal("fetch", doFetch);
		const config = { engine: "http", endpoint: "http://127.0.0.1:18206", policies: PERMIT_ALL };
		await expect(
			CedarPolicyRuleCollector.create({ ...config, requireConfirmedRevision: true }),
		).rejects.toThrow(/requireConfirmedRevision = true cannot be used with the "http" engine/);
		expect(calls).toHaveLength(0);
		// …and the agent is not held for the refused collector.
		await expect(CedarPolicyRuleCollector.create(config)).resolves.toBeDefined();
	});

	it("denies and logs when the agent is down after boot", async () => {
		let up = true;
		const { doFetch } = agent(() => {
			if (!up) throw refused();
			return json(200, ALLOW);
		});
		vi.stubGlobal("fetch", doFetch);
		const logger = silentLogger();
		const collector = await CedarPolicyRuleCollector.create(
			{
				engine: "http",
				endpoint: "http://127.0.0.1:18202",
				policies: PERMIT_ALL,
			},
			{ logger },
		);
		const [rule] = await collector.collect(context);
		if (!isAsyncRule(rule)) throw new Error("expected an AsyncRule");
		const attrs = new Map<string, unknown>([
			["userId", "alice"],
			["requestAction", "read"],
			["requestResourceType", "Document"],
		]);
		expect(await rule.decide(attrs, NEVER_ABORTS)).toBe(true);
		up = false;
		expect(await rule.decide(attrs, NEVER_ABORTS)).toBe(false);
		expect(logger.error).toHaveBeenCalledOnce();
		expect(JSON.stringify((logger.error as ReturnType<typeof vi.fn>).mock.calls[0])).toMatch(
			/"engine":"http".*authorization call failed/,
		);
	});

	it("says at boot which engine was selected, and why", async () => {
		const { doFetch } = agent();
		vi.stubGlobal("fetch", doFetch);
		const logger = silentLogger();
		await CedarPolicyRuleCollector.create(
			{ engine: "http", endpoint: "http://127.0.0.1:18203", policies: PERMIT_ALL },
			{ logger },
		);
		const lines = (logger.info as ReturnType<typeof vi.fn>).mock.calls.map((call) =>
			JSON.stringify(call),
		);
		expect(lines[0]).toMatch(/"engine":"http".*cedar engine selected by config/);
		expect(lines[1]).toMatch(
			/"endpoint":"http:\/\/127\.0\.0\.1:18203".*"policies":1.*loaded into the engine/,
		);
	});
});
