// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The HTTP engine through Node's real `fetch`, against a fake cedar-agent
 * (`fakeCedarAgent.mts`): a local `node:http` server started per suite,
 * programmed per test, recording what it received (#269). Nothing here stubs
 * `fetch` or the engine. `httpEngine.test.mts` pins what the engine makes of
 * answers a scripted `fetch` hands it; this file pins what actually crosses
 * the wire, and how each way the wire can fail comes out — as a
 * `CedarEngineError` from the engine, and as a logged deny with a `failed`
 * evaluation from the rule.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
	AnyRule,
	Attributes,
	Logger,
	RuleEvaluation,
	RuleOutcome,
} from "@o3co/auth.policy-verifier.core";
import { evaluate, RuleTimeoutError } from "@o3co/auth.policy-verifier.core";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { CedarPolicyRuleCollector } from "../CedarPolicyRuleCollector.mjs";
import { CedarEngineError, type CedarEngineLoadContext } from "../engine.mjs";
import { CEDAR_AUTHENTICATION_ENV, createCedarHttpEngine } from "../httpEngine.mjs";
import type { CedarRequest } from "../mapping.mjs";
import { computePolicyRevision, loadPolicySource, type PolicySource } from "../policySource.mjs";
import {
	authorizeWith,
	cedarAgent,
	decision,
	FakeCedarAgent,
	type Handler,
	sendJson,
} from "./fakeCedarAgent.mjs";
// Registers the http engine under "http" for the collector-level cases.
import "../index.mjs";

const PERMIT = "permit(principal, action, resource);";
const FORBID = 'forbid(principal, action, resource) when { resource.owner != "alice" };';

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

function loadContext(config: Record<string, unknown>): CedarEngineLoadContext {
	return { config, logger: silentLogger() };
}

/** Two policies, one per file — the layout the http engine asks for. */
function policySet(): PolicySource {
	const files = [
		{ name: "10-permit.cedar", source: "/policies/10-permit.cedar", text: PERMIT },
		{ name: "20-forbid.cedar", source: "/policies/20-forbid.cedar", text: FORBID },
	];
	return {
		files,
		text: `${PERMIT}\n${FORBID}`,
		description: "/policies",
		revision: computePolicyRevision(files),
	};
}

function request(): CedarRequest {
	const principal = { type: "User", id: 'al"ice' };
	const resource = { type: "App::Document", id: "42" };
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

const NEVER_ABORTS = new AbortController().signal;

function parsed(body: string): unknown {
	return JSON.parse(body);
}

/** An engine of its own over the global `fetch`, loaded against `endpoint`. */
async function loadedAgainst(endpoint: string, config: Record<string, unknown> = {}) {
	const loaded = await createCedarHttpEngine({ env: {} }).load(
		policySet(),
		loadContext({ endpoint, ...config }),
	);
	if (!loaded.async) throw new Error("the http engine answers asynchronously");
	return loaded;
}

let agent: FakeCedarAgent;

beforeAll(async () => {
	agent = await FakeCedarAgent.start();
});

afterEach(() => {
	agent.reset();
});

afterAll(async () => {
	await agent.stop();
});

describe("cedarHttpEngine over the wire — what reaches the agent", () => {
	it("PUTs the policy set to <base>/v1/policies: one { id, content } per file, JSON, the token verbatim", async () => {
		await loadedAgainst(`${agent.origin}/cedar/`, { authentication: "agent-token" });

		expect(agent.received).toHaveLength(1);
		const [put] = agent.received;
		expect(put.method).toBe("PUT");
		// The trailing slash of the base URL does not double up, and nothing is appended.
		expect(put.path).toBe("/cedar/v1/policies");
		expect(put.headers["content-type"]).toBe("application/json");
		// cedar-agent compares the header to its --authentication value: no scheme.
		expect(put.headers.authorization).toBe("agent-token");
		expect(parsed(put.body)).toEqual([
			{ id: "10-permit", content: PERMIT },
			{ id: "20-forbid", content: FORBID },
		]);
	});

	it("POSTs cedar-agent's AuthorizationCall to <base>/v1/is_authorized: literals, entities inline, the token verbatim", async () => {
		const loaded = await loadedAgainst(`${agent.origin}/cedar`, {
			authentication: "agent-token",
		});
		await loaded.isAuthorized(request(), NEVER_ABORTS);

		expect(agent.received).toHaveLength(2);
		const post = agent.received[1];
		expect(post.method).toBe("POST");
		expect(post.path).toBe("/cedar/v1/is_authorized");
		expect(post.headers["content-type"]).toBe("application/json");
		expect(post.headers.authorization).toBe("agent-token");
		expect(parsed(post.body)).toEqual({
			principal: 'User::"al\\"ice"',
			action: 'Action::"read"',
			resource: 'App::Document::"42"',
			context: { mfa: true },
			entities: request().entities,
		});
	});

	it("sends no Authorization header at all when no token is configured", async () => {
		const loaded = await loadedAgainst(agent.origin);
		await loaded.isAuthorized(request(), NEVER_ABORTS);

		expect(agent.received.map((received) => received.method)).toEqual(["PUT", "POST"]);
		for (const received of agent.received) {
			expect(received.headers).not.toHaveProperty("authorization");
		}
	});

	it("sends CEDAR_AUTHENTICATION when the config names no token", async () => {
		const loaded = await createCedarHttpEngine({
			env: { [CEDAR_AUTHENTICATION_ENV]: "from-env" },
		}).load(policySet(), loadContext({ endpoint: agent.origin }));
		if (!loaded.async) throw new Error("the http engine answers asynchronously");
		await loaded.isAuthorized(request(), NEVER_ABORTS);

		expect(agent.received.map((received) => received.headers.authorization)).toEqual([
			"from-env",
			"from-env",
		]);
	});
});

describe("cedarHttpEngine over the wire — reading the answer", () => {
	it("reads an Allow and a Deny, with their determining policies and errors", async () => {
		const loaded = await loadedAgainst(agent.origin);

		agent.answer(cedarAgent(decision("Allow", ["10-permit"])));
		expect(await loaded.isAuthorized(request(), NEVER_ABORTS)).toEqual({
			decision: "allow",
			reason: ["10-permit"],
			errors: [],
		});

		agent.answer(cedarAgent(decision("Deny", ["20-forbid"], ["policy 10-permit: no dept"])));
		expect(await loaded.isAuthorized(request(), NEVER_ABORTS)).toEqual({
			decision: "deny",
			reason: ["20-forbid"],
			errors: ["policy 10-permit: no dept"],
		});
	});

	it("names no revision, whatever the agent claims — cedar-agent does not say what it ran (#244)", async () => {
		const loaded = await loadedAgainst(agent.origin);
		agent.answer(
			cedarAgent({ ...decision("Allow", ["10-permit"]), revision: policySet().revision }),
		);
		const answer = await loaded.isAuthorized(request(), NEVER_ABORTS);
		expect(answer).not.toHaveProperty("revision");
	});
});

describe("cedarHttpEngine over the wire — a failed call rejects with CedarEngineError", () => {
	const failures: Array<[string, Handler, RegExp]> = [
		[
			"a 500 in cedar-agent's error shape",
			(_request, response) =>
				sendJson(response, 500, {
					reason: "Internal Server Error",
					description: "the storage is gone",
					code: 500,
				}),
			/answered 500 to an authorization call: the storage is gone/,
		],
		[
			"a 400 in cedar-agent's error shape",
			(_request, response) =>
				sendJson(response, 400, { description: "while parsing context, found a `null`" }),
			/answered 400 to an authorization call: while parsing context/,
		],
		[
			"a 503 with an HTML body",
			(_request, response) => {
				response.writeHead(503, { "content-type": "text/html" });
				response.end("<html>maintenance</html>");
			},
			/answered 503 to an authorization call: Service Unavailable/,
		],
		[
			"a 404 — an agent without the route",
			(_request, response) => {
				response.writeHead(404);
				response.end();
			},
			/answered 404 to an authorization call: Not Found/,
		],
		[
			"a 3xx with no Location — nothing to follow, so non-2xx",
			(_request, response) => {
				response.writeHead(300);
				response.end();
			},
			/answered 300 to an authorization call/,
		],
		[
			"a 200 whose body is not JSON",
			(_request, response) => {
				response.writeHead(200, { "content-type": "application/json" });
				response.end("<html>");
			},
			/answered something that is not a decision/,
		],
		[
			"a 200 with an empty body",
			(_request, response) => {
				response.writeHead(200, { "content-type": "application/json" });
				response.end();
			},
			/answered something that is not a decision/,
		],
		[
			"a 204",
			(_request, response) => {
				response.writeHead(204);
				response.end();
			},
			/answered something that is not a decision/,
		],
		[
			"a 200 cut off mid-body — the connection drops before content-length is reached",
			(_request, response) => {
				response.writeHead(200, { "content-type": "application/json", "content-length": 200 });
				response.write('{"decision":"Allow","diagnostics":{"reason":[');
				setImmediate(() => response.socket?.destroy());
			},
			/answered something that is not a decision/,
		],
		[
			"a 200 JSON array",
			(_request, response) => sendJson(response, 200, [decision("Allow")]),
			/answered an unknown decision undefined/,
		],
		[
			"a 200 decision without diagnostics",
			(_request, response) => sendJson(response, 200, { decision: "Allow" }),
			/without well-formed diagnostics/,
		],
		[
			"a 200 decision that is neither Allow nor Deny",
			(_request, response) => sendJson(response, 200, { ...decision("Allow"), decision: "Permit" }),
			/unknown decision "Permit"/,
		],
		[
			"a connection dropped before any answer",
			(_request, response) => response.socket?.destroy(),
			/cedar engine at .*\/v1\/is_authorized is unreachable: fetch failed/,
		],
		[
			"a redirect loop — fetch gives up",
			(request, response) => {
				response.writeHead(307, { location: request.path });
				response.end();
			},
			/cedar engine at .*\/v1\/is_authorized is unreachable: fetch failed/,
		],
	];

	it.each(failures)("%s", async (_label, authorize, expected) => {
		const loaded = await loadedAgainst(agent.origin);
		agent.answer(authorizeWith(authorize));
		const failure = loaded.isAuthorized(request(), NEVER_ABORTS);
		await expect(failure).rejects.toThrow(CedarEngineError);
		await expect(failure).rejects.toThrow(expected);
	});

	it("an agent that went away after boot — connection refused", async () => {
		const gone = await FakeCedarAgent.start();
		const loaded = await loadedAgainst(gone.origin);
		await gone.stop();
		const failure = loaded.isAuthorized(request(), NEVER_ABORTS);
		await expect(failure).rejects.toThrow(CedarEngineError);
		await expect(failure).rejects.toThrow(
			new RegExp(`cedar engine at ${gone.origin}/v1/is_authorized is unreachable: fetch failed`),
		);
	});
});

describe("cedarHttpEngine over the wire — the deadline", () => {
	it("rejects with the signal's reason when the deadline passes before the agent answers", async () => {
		const loaded = await loadedAgainst(agent.origin);
		agent.answer(authorizeWith((_request, response) => agent.hold(response)));
		const controller = new AbortController();
		const reason = new Error("rule deadline");
		const arrived = agent.nextRequest();
		const failure = loaded.isAuthorized(request(), controller.signal);
		// Aborted once the agent holds the call — no timer, so no race with it.
		await arrived;
		controller.abort(reason);
		await expect(failure).rejects.toBe(reason);
	});
});

describe("cedarHttpEngine over the wire — boot", () => {
	it("refuses to start naming the endpoint when the connection is refused", async () => {
		// One attempt: `retryMs` is not shorter than the deadline, so the first
		// refusal is the last. With room for a retry, the last attempt runs under
		// whatever is left of the deadline — a millisecond, when a timer
		// overshoots — and can time out before the refusal arrives; the engine
		// then reports the refused agent as "reachable, but the request timed
		// out". That is a finding of #269, not pinned here because it is a race.
		// The retry loop itself is pinned against a scripted fetch.
		const gone = await FakeCedarAgent.start();
		await gone.stop();
		const load = createCedarHttpEngine({ env: {}, loadTimeoutMs: 1000, retryMs: 1000 }).load(
			policySet(),
			loadContext({ endpoint: gone.origin }),
		);
		await expect(load).rejects.toThrow(CedarEngineError);
		await expect(load).rejects.toThrow(
			new RegExp(
				`cedar engine at ${gone.origin} is unreachable — could not load the policy set from /policies within 1000 ms \\(1 attempts\\): fetch failed`,
			),
		);
	});

	it("says the agent is reachable but not answering when the load deadline passes on an open connection", async () => {
		// The real `fetch` rejects with the timeout signal's own reason, a
		// DOMException named TimeoutError — the name the engine tells this
		// case apart by. The agent never answers, so the outcome does not
		// depend on how long the deadline is.
		agent.answer((_request, response) => agent.hold(response));
		const load = createCedarHttpEngine({ env: {}, loadTimeoutMs: 100, retryMs: 20 }).load(
			policySet(),
			loadContext({ endpoint: agent.origin }),
		);
		await expect(load).rejects.toThrow(
			/did not accept the policy set from \/policies within 100 ms — reachable, but the request timed out \(1 attempts\)/,
		);
		expect(agent.received).toHaveLength(1);
	});

	it("refuses to start when the agent refuses the set, in the agent's words and naming the ids sent", async () => {
		agent.answer((_request, response) =>
			sendJson(response, 400, {
				reason: "You have malformed a bad request",
				description: "policy 20-forbid: unexpected token",
				code: 400,
			}),
		);
		await expect(
			createCedarHttpEngine({ env: {} }).load(policySet(), loadContext({ endpoint: agent.origin })),
		).rejects.toThrow(
			/refused the policy set from \/policies \(400; policies: 10-permit, 20-forbid\): policy 20-forbid: unexpected token/,
		);
	});

	it("names the token when the agent answers 401", async () => {
		agent.answer((_request, response) =>
			sendJson(response, 401, {
				reason: "Unauthorized",
				description: "The request requires user authentication.",
				code: 401,
			}),
		);
		await expect(
			createCedarHttpEngine({ env: {} }).load(policySet(), loadContext({ endpoint: agent.origin })),
		).rejects.toThrow(/requires a token and none was sent/);
		await expect(
			createCedarHttpEngine({ env: {} }).load(
				policySet(),
				loadContext({ endpoint: agent.origin, authentication: "wrong" }),
			),
		).rejects.toThrow(/did not accept the token from authentication \(401\)/);
		expect(agent.received.map((received) => received.headers.authorization)).toEqual([
			undefined,
			"wrong",
		]);
	});
});

// --- the rule ------------------------------------------------------------------

describe("CedarPolicyRuleCollector over the wire", () => {
	let policyDir: string;
	let loadedRevision: string;
	/** The registered engine is one per process: each collector gets an agent of its own by base path. */
	let agents = 0;

	beforeAll(() => {
		policyDir = mkdtempSync(join(tmpdir(), "cedar-http-fake-agent-"));
		writeFileSync(join(policyDir, "10-permit.cedar"), PERMIT);
		writeFileSync(join(policyDir, "20-forbid.cedar"), FORBID);
		loadedRevision = loadPolicySource({ policyDir }).revision;
	});

	afterAll(() => {
		rmSync(policyDir, { recursive: true, force: true });
	});

	const context = {
		subject: { sub: "user-1" },
		resource: { raw: "document:42", resourceType: "document", resourceId: "42" },
		action: "read",
		signal: NEVER_ABORTS,
	};

	const attrs = (): Attributes =>
		new Map<string, unknown>([
			["userId", "alice"],
			["requestAction", "read"],
			["requestResourceType", "Document"],
			["requestResourceId", "42"],
		]);

	async function rule(config: Record<string, unknown> = {}) {
		agents++;
		const logger = silentLogger();
		const endpoint = `${agent.origin}/rule-${agents}`;
		const collector = await CedarPolicyRuleCollector.create(
			{ engine: "http", endpoint, policyDir, ...config },
			{ logger },
		);
		const [only] = await collector.collect(context);
		return { rule: only as AnyRule, logger, endpoint };
	}

	function outcomeOf(decided: Awaited<ReturnType<typeof evaluate>>): RuleOutcome {
		const [group] = decided.reason.groups;
		return group.evaluated[0];
	}

	function unconfirmed(status: "completed" | "failed"): RuleEvaluation {
		return { status, revision: null, loadedRevision };
	}

	it("permits, reporting the revision it pushed as loaded and none as evaluated (#244)", async () => {
		const { rule: permit } = await rule();
		expect(loadedRevision).toMatch(/^sha256:[0-9a-f]{64}$/);
		agent.answer(cedarAgent(decision("Allow", ["10-permit"])));

		const decided = await evaluate(attrs(), [permit]);
		expect(decided.decision).toBe("allow");
		expect(outcomeOf(decided)).toEqual({
			code: "cedar_deny",
			message: "Denied by Cedar policy",
			passed: true,
			evaluation: unconfirmed("completed"),
		});
		// What was pushed is what the revision was computed over.
		expect(parsed(agent.received[0].body)).toEqual([
			{ id: "10-permit", content: PERMIT },
			{ id: "20-forbid", content: FORBID },
		]);
	});

	it("forbids on a determining forbid, reporting the same revisions", async () => {
		const { rule: forbid, logger } = await rule();
		agent.answer(cedarAgent(decision("Deny", ["20-forbid"])));

		const decided = await evaluate(attrs(), [forbid]);
		expect(decided).toMatchObject({ decision: "deny", code: "cedar_deny" });
		expect(outcomeOf(decided)).toMatchObject({
			passed: false,
			evaluation: unconfirmed("completed"),
		});
		// A forbid is the policies' answer, not a fault.
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("does not take an agent's word for the revision — it cannot vouch for what it ran (#244)", async () => {
		const { rule: permit } = await rule();
		agent.answer(cedarAgent({ ...decision("Allow", ["10-permit"]), revision: loadedRevision }));
		const decided = await evaluate(attrs(), [permit]);
		expect(outcomeOf(decided).evaluation).toEqual(unconfirmed("completed"));
	});

	it("refuses requireConfirmedRevision at boot, before anything reaches the agent (#244)", async () => {
		await expect(rule({ requireConfirmedRevision: true })).rejects.toThrow(
			/requireConfirmedRevision = true cannot be used with the "http" engine/,
		);
		expect(agent.received).toEqual([]);
	});

	const failures: Array<[string, Handler]> = [
		["a 500", (_request, response) => sendJson(response, 500, { description: "boom" })],
		[
			"a body that is not JSON",
			(_request, response) => {
				response.writeHead(200, { "content-type": "application/json" });
				response.end("not json");
			},
		],
		["a connection dropped before any answer", (_request, response) => response.socket?.destroy()],
		[
			"a 3xx with no Location",
			(_request, response) => {
				response.writeHead(302);
				response.end();
			},
		],
	];

	it.each(failures)("fails closed on %s: a logged deny, evaluation failed", async (_l, handler) => {
		const { rule: failing, logger } = await rule();
		agent.answer(authorizeWith(handler));
		const decided = await evaluate(attrs(), [failing]);
		expect(decided).toMatchObject({ decision: "deny", code: "cedar_deny" });
		expect(outcomeOf(decided)).toMatchObject({ passed: false, evaluation: unconfirmed("failed") });
		expect(JSON.stringify((logger.error as ReturnType<typeof vi.fn>).mock.calls)).toMatch(
			/"engine":"http".*authorization call failed — denying/,
		);
	});

	it("fails closed when the agent is gone after boot — connection refused", async () => {
		const gone = await FakeCedarAgent.start();
		const collector = await CedarPolicyRuleCollector.create(
			{ engine: "http", endpoint: gone.origin, policyDir },
			{ logger: silentLogger() },
		);
		const [refused] = await collector.collect(context);
		await gone.stop();
		const decided = await evaluate(attrs(), [refused]);
		expect(decided).toMatchObject({ decision: "deny", code: "cedar_deny" });
		expect(outcomeOf(decided)).toMatchObject({ passed: false, evaluation: unconfirmed("failed") });
	});

	it("overruns the rule deadline when the agent does not answer: RuleTimeoutError, never a pass", async () => {
		const { rule: slow } = await rule();
		agent.answer(authorizeWith((_request, response) => agent.hold(response)));
		// The agent never answers, so the outcome does not depend on the budget.
		await expect(evaluate(attrs(), [slow], { ruleTimeoutMs: 50 })).rejects.toBeInstanceOf(
			RuleTimeoutError,
		);
		expect(agent.received.map((received) => received.method)).toEqual(["PUT", "POST"]);
	});

	it("overruns the rule deadline when the agent stalls mid-body, too", async () => {
		const { rule: slow } = await rule();
		agent.answer(
			authorizeWith((_request, response) => {
				response.writeHead(200, { "content-type": "application/json", "content-length": 200 });
				response.write('{"decision":"Allow",');
				agent.hold(response);
			}),
		);
		await expect(evaluate(attrs(), [slow], { ruleTimeoutMs: 50 })).rejects.toBeInstanceOf(
			RuleTimeoutError,
		);
	});
});
