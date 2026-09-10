// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The HTTP engine against a scripted `fetch`: what it sends cedar-agent, what
 * it makes of the answers, and how it fails. The wire shape is cedar-agent's
 * (`PUT /v1/policies` with `[{ id, content }]`, `POST /v1/is_authorized` with
 * entity references as `Type::"id"` literals and a `{ decision, diagnostics }`
 * answer) — pinned here so a change on either side shows up as a test.
 */

import type { Logger } from "@o3co/auth.policy-verifier.core";
import { evaluate, isAsyncRule } from "@o3co/auth.policy-verifier.core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CedarPolicyRuleCollector } from "../CedarPolicyRuleCollector.mjs";
import { CedarEngineError, type CedarEngineLoadContext } from "../engine.mjs";
import {
	CEDAR_AUTHENTICATION_ENV,
	CEDAR_ENDPOINT_ENV,
	createCedarHttpEngine,
	DEFAULT_CEDAR_ENDPOINT,
	entityUidLiteral,
} from "../httpEngine.mjs";
import type { CedarRequest } from "../mapping.mjs";
import type { PolicySource } from "../policySource.mjs";
// Registers the http engine under "http" for the collector-level cases.
import "../index.mjs";

const PERMIT_ALL = "permit(principal, action, resource);";

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
	return { files: [{ source: "policies (inline)", text }], text, description: "inline policies" };
}

function dir(files: Array<[string, string]>): PolicySource {
	return {
		files: files.map(([name, text]) => ({ source: `/etc/verifier/policies/${name}`, text })),
		text: files.map(([, text]) => text).join("\n"),
		description: "/etc/verifier/policies",
	};
}

function json(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
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
		const engine = createCedarHttpEngine({ fetch: doFetch, env: {} });
		const forbid = "forbid(principal, action, resource) when { context.suspended == true };";
		await loadAsync(
			engine,
			dir([
				["10-permit.cedar", PERMIT_ALL],
				["20-forbid.cedar", forbid],
			]),
		);
		expect(calls).toHaveLength(1);
		expect(calls[0].url).toBe(`${DEFAULT_CEDAR_ENDPOINT}/v1/policies`);
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
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env: {} }), inline(PERMIT_ALL));
		expect(JSON.parse(String(calls[0].init.body))).toEqual([
			{ id: "policies", content: PERMIT_ALL },
		]);

		await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: {} }),
			dir([["blank.cedar", "  \n"]]),
		);
		expect(JSON.parse(String(calls[1].init.body))).toEqual([]);
	});

	it("refuses a file whose name yields an empty policy id, before sending anything", async () => {
		const { doFetch, calls } = agent();
		const engine = createCedarHttpEngine({ fetch: doFetch, env: {} });
		await expect(engine.load(dir([[".cedar", PERMIT_ALL]]), loadContext())).rejects.toThrow(
			/"\/etc\/verifier\/policies\/\.cedar" yields an empty policy id/,
		);
		expect(calls).toHaveLength(0);
		// The endpoint was released: a proper set loads afterwards.
		await loadAsync(engine, inline(PERMIT_ALL));
	});

	it("sends the agent's authorization token verbatim: config over environment", async () => {
		const { doFetch, calls } = agent();
		const env = { [CEDAR_AUTHENTICATION_ENV]: "from-env" };
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env }), inline(PERMIT_ALL));
		expect(headersOf(calls[0]).authorization).toBe("from-env");

		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env }), inline(PERMIT_ALL), {
			authentication: "from-config",
		});
		expect(headersOf(calls[1]).authorization).toBe("from-config");
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
		const engine = createCedarHttpEngine({ fetch: doFetch, env: {} });
		await expect(
			engine.load(dir([["20-forbid.cedar", "forbid(when;"]]), loadContext()),
		).rejects.toThrow(
			/refused the policy set from \/etc\/verifier\/policies \(400; policies: 20-forbid\): .*policy 20-forbid: unexpected token/,
		);
	});

	it("retries an unreachable agent until the load deadline, then refuses to start naming it", async () => {
		let attempts = 0;
		const doFetch = vi.fn(async () => {
			attempts++;
			throw new TypeError("fetch failed: ECONNREFUSED");
		}) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({
			fetch: doFetch,
			env: {},
			loadTimeoutMs: 40,
			retryMs: 10,
		});
		await expect(engine.load(inline(PERMIT_ALL), loadContext())).rejects.toThrow(
			new RegExp(
				`cedar engine at ${DEFAULT_CEDAR_ENDPOINT} is unreachable — could not load .* within 40 ms \\(\\d+ attempts\\): fetch failed`,
			),
		);
		expect(attempts).toBeGreaterThan(1);
	});

	it("says so when the agent is reachable but does not answer within the load deadline", async () => {
		let attempts = 0;
		const doFetch = vi.fn(async () => {
			attempts++;
			throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
		}) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({
			fetch: doFetch,
			env: {},
			loadTimeoutMs: 40,
			retryMs: 10,
		});
		await expect(engine.load(inline(PERMIT_ALL), loadContext())).rejects.toThrow(
			/did not accept the policy set from inline policies within 40 ms — reachable, but the request timed out \(1 attempts\)/,
		);
		expect(attempts).toBe(1);
	});

	it("comes up when the agent does — a compose sibling a few hundred milliseconds behind", async () => {
		let attempts = 0;
		const { doFetch } = agent();
		const flaky = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			attempts++;
			if (attempts < 3) throw new TypeError("fetch failed: ECONNREFUSED");
			return doFetch(input, init);
		}) as unknown as typeof fetch;
		const engine = createCedarHttpEngine({ fetch: flaky, env: {}, loadTimeoutMs: 500, retryMs: 5 });
		await loadAsync(engine, inline(PERMIT_ALL));
		expect(attempts).toBe(3);
	});

	it("runs one policy set per agent — a second load against the same endpoint is refused", async () => {
		const { doFetch } = agent();
		const engine = createCedarHttpEngine({ fetch: doFetch, env: {} });
		await loadAsync(engine, inline(PERMIT_ALL));
		await expect(engine.load(dir([["other.cedar", PERMIT_ALL]]), loadContext())).rejects.toThrow(
			/already holds the policy set from inline policies — PUT \/v1\/policies replaces an agent's whole set/,
		);
	});

	it("refuses the second of two concurrent loads too, and frees the endpoint when a load fails", async () => {
		const { doFetch } = agent();
		const engine = createCedarHttpEngine({ fetch: doFetch, env: {} });
		const results = await Promise.allSettled([
			engine.load(inline(PERMIT_ALL), loadContext()),
			engine.load(dir([["other.cedar", PERMIT_ALL]]), loadContext()),
		]);
		expect(results.map((result) => result.status)).toEqual(["fulfilled", "rejected"]);

		const refusing = vi.fn(async () => json(400, { description: "no" })) as unknown as typeof fetch;
		const failing = createCedarHttpEngine({
			fetch: refusing,
			env: {},
			loadTimeoutMs: 40,
			retryMs: 10,
		});
		await expect(failing.load(inline(PERMIT_ALL), loadContext())).rejects.toThrow(/refused/);
		// The failed load did not leave the endpoint marked as held.
		await expect(failing.load(inline(PERMIT_ALL), loadContext())).rejects.toThrow(/refused/);
	});
});

describe("cedarHttpEngine — where the agent is", () => {
	it("prefers the config endpoint, then CEDAR_ENDPOINT, then the loopback default", async () => {
		const { doFetch, calls } = agent();
		const env = { [CEDAR_ENDPOINT_ENV]: "http://localhost:9001" };
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env }), inline(PERMIT_ALL), {
			endpoint: "http://127.0.0.1:9002/cedar/",
		});
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env }), inline(PERMIT_ALL));
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env: {} }), inline(PERMIT_ALL));
		expect(calls.map((call) => call.url)).toEqual([
			"http://127.0.0.1:9002/cedar/v1/policies",
			"http://localhost:9001/v1/policies",
			`${DEFAULT_CEDAR_ENDPOINT}/v1/policies`,
		]);
	});

	it("accepts https to any host and plain http to loopback only", async () => {
		const { doFetch, calls } = agent();
		await loadAsync(createCedarHttpEngine({ fetch: doFetch, env: {} }), inline(PERMIT_ALL), {
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
			await loadAsync(createCedarHttpEngine({ fetch: doFetch, env: {} }), inline(PERMIT_ALL), {
				endpoint,
			});
		}
		expect(calls.at(-5)?.url).toBe("http://[::1]:8180/v1/policies");
		// Look-alikes are routable names and stay refused.
		for (const endpoint of ["http://127.0.0.1.attacker.test", "http://localhost.attacker.test"]) {
			await expect(
				createCedarHttpEngine({ fetch: doFetch, env: {} }).load(
					inline(PERMIT_ALL),
					loadContext({ endpoint }),
				),
			).rejects.toThrow(/plain http to a routable host/);
		}
		await expect(
			createCedarHttpEngine({ fetch: doFetch, env: {} }).load(
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
			createCedarHttpEngine({ fetch: doFetch, env: {} }).load(
				inline(PERMIT_ALL),
				loadContext({ authentication: 7 }),
			),
		).rejects.toThrow(/authentication must be a non-empty string/);
	});
});

describe("cedarHttpEngine — isAuthorized", () => {
	it("POSTs cedar-agent's AuthorizationCall: entity references as literals, entities inline, the rule's signal", async () => {
		const { doFetch, calls } = agent();
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: {} }),
			inline(PERMIT_ALL),
		);
		const controller = new AbortController();
		const answer = await loaded.isAuthorized(request(), controller.signal);
		expect(answer).toEqual({ decision: "allow", reason: ["policies"], errors: [] });

		const call = calls[1];
		expect(call.url).toBe(`${DEFAULT_CEDAR_ENDPOINT}/v1/is_authorized`);
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
			createCedarHttpEngine({ fetch: doFetch, env: {} }),
			inline(PERMIT_ALL),
		);
		expect(await loaded.isAuthorized(request(), NEVER_ABORTS)).toEqual({
			decision: "deny",
			reason: ["20-forbid"],
			errors: ["policy 10-permit: attribute dept missing"],
		});
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
				createCedarHttpEngine({ fetch: agent(response).doFetch, env: {} }),
				inline(PERMIT_ALL),
			);
			const failure = loaded.isAuthorized(request(), NEVER_ABORTS);
			await expect(failure).rejects.toThrow(CedarEngineError);
			await expect(failure).rejects.toThrow(expected);
		}
	});

	it("rejects with CedarEngineError when the agent is unreachable, and with the signal's reason when aborted", async () => {
		const { doFetch } = agent(() => {
			throw new TypeError("fetch failed: ECONNRESET");
		});
		const loaded = await loadAsync(
			createCedarHttpEngine({ fetch: doFetch, env: {} }),
			inline(PERMIT_ALL),
		);
		await expect(loaded.isAuthorized(request(), NEVER_ABORTS)).rejects.toThrow(
			/cedar engine at .*\/v1\/is_authorized is unreachable: fetch failed/,
		);

		const reason = new Error("deadline");
		const aborting = agent(() => {
			throw new DOMException("The operation was aborted", "AbortError");
		});
		const set = await loadAsync(
			createCedarHttpEngine({ fetch: aborting.doFetch, env: {} }),
			inline(PERMIT_ALL),
		);
		const controller = new AbortController();
		controller.abort(reason);
		await expect(set.isAuthorized(request(), controller.signal)).rejects.toBe(reason);
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

	it("denies and logs, never abstains, when the agent is down after boot", async () => {
		let up = true;
		const { doFetch } = agent(() => {
			if (!up) throw new TypeError("fetch failed: ECONNREFUSED");
			return json(200, ALLOW);
		});
		vi.stubGlobal("fetch", doFetch);
		const logger = silentLogger();
		const collector = await CedarPolicyRuleCollector.create(
			{
				engine: "http",
				endpoint: "http://127.0.0.1:18202",
				policies: PERMIT_ALL,
				onNoDeterminingPolicy: "abstain",
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
