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
 *
 * A case marked `it.fails` is the documented contract, which the engine does
 * not meet over the real `fetch`: a finding, named in the comment above it.
 * It turns red when the engine is fixed, and is then made an ordinary `it`.
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
import { agentPolicyId, CEDAR_AUTHENTICATION_ENV, createCedarHttpEngine } from "../httpEngine.mjs";
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

/**
 * The id a policy of {@link policySet} — and of the collector cases' `policyDir`,
 * the same two files — is pushed under: its file id, under the load's mark
 * (#283). An agent holding the pushed set answers with these.
 */
const pushed = (id: string) => agentPolicyId(id, policySet().revision);

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

/** An engine of its own over the global `fetch` (or `fetch`, when given), loaded against `endpoint`. */
async function loadedAgainst(
	endpoint: string,
	config: Record<string, unknown> = {},
	fetch?: typeof globalThis.fetch,
) {
	const loaded = await createCedarHttpEngine({ env: {}, fetch }).load(
		policySet(),
		loadContext({ endpoint, ...config }),
	);
	if (!loaded.async) throw new Error("the http engine answers asynchronously");
	return loaded;
}

/**
 * An engine of its own over the global `fetch`, loaded against `endpoint`,
 * and a promise that resolves once `fetch` has handed the engine the
 * `Response` to an authorization call — its status and headers are in, and
 * the body is what the engine reads next. The `fetch` is the real one, called
 * with the engine's own arguments and returning its own result: this only
 * observes when it resolves, which every Node's `fetch` does. (The body-chunk
 * diagnostics channel this used to wait on is not published by the undici
 * that Node 22 ships, so the case it served was skipped there.)
 */
async function loadedObservingAnswers(endpoint: string) {
	let answered!: () => void;
	const headersIn = new Promise<void>((resolve) => {
		answered = resolve;
	});
	const observing: typeof fetch = async (input, init) => {
		const response = await globalThis.fetch(input, init);
		if (String(input).endsWith("/v1/is_authorized")) answered();
		return response;
	};
	return { loaded: await loadedAgainst(endpoint, {}, observing), headersIn };
}

let agent: FakeCedarAgent;
/** A second server: whatever it receives went somewhere the engine was not pointed at. */
let stranger: FakeCedarAgent;

beforeAll(async () => {
	[agent, stranger] = await Promise.all([FakeCedarAgent.start(), FakeCedarAgent.start()]);
});

afterEach(() => {
	agent.reset();
	stranger.reset();
});

afterAll(async () => {
	await Promise.all([agent.stop(), stranger.stop()]);
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
			{ id: pushed("10-permit"), content: PERMIT },
			{ id: pushed("20-forbid"), content: FORBID },
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

		agent.answer(cedarAgent(decision("Allow", [pushed("10-permit")])));
		expect(await loaded.isAuthorized(request(), NEVER_ABORTS)).toEqual({
			decision: "allow",
			reason: ["10-permit"],
			errors: [],
		});

		const error = `error occurred while evaluating policy \`${pushed("10-permit")}\`: no dept`;
		agent.answer(cedarAgent(decision("Deny", [pushed("20-forbid")], [error])));
		expect(await loaded.isAuthorized(request(), NEVER_ABORTS)).toEqual({
			decision: "deny",
			reason: ["20-forbid"],
			errors: [error],
		});
	});

	it("names no revision, whatever the agent claims — cedar-agent does not say what it ran (#244)", async () => {
		const loaded = await loadedAgainst(agent.origin);
		agent.answer(
			cedarAgent({ ...decision("Allow", [pushed("10-permit")]), revision: policySet().revision }),
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
			// Not "answered something that is not a decision" (#271): the agent
			// never finished answering.
			/broke off its answer to an authorization call: terminated/,
		],
		[
			// Refused once past the bound, not read to the end and parsed (#271).
			"a 200 larger than CEDAR_ANSWER_MAX_BYTES",
			(_request, response) => {
				response.writeHead(200, { "content-type": "application/json" });
				response.end(`{"decision":"Allow","padding":"${"x".repeat(1024 * 1024)}"}`);
			},
			/answered an authorization call with more than 1 MiB — refused; set maxAnswerBytes higher if its answers are this large$/,
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
			// The cause undici keeps on the error is named (#271).
			/cedar engine at .*\/v1\/is_authorized is unreachable: fetch failed: .+$/,
		],
		[
			// Before #270 `fetch` followed this until it gave up ("fetch failed").
			// Now the first 3xx is answered as the non-2xx it is.
			"a redirect loop — refused at the first hop",
			(request, response) => {
				response.writeHead(307, { location: request.path });
				response.end();
			},
			/cedar engine at .*answered 307 to an authorization call/,
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
			new RegExp(
				`cedar engine at ${gone.origin}/v1/is_authorized is unreachable: fetch failed: connect ECONNREFUSED 127\\.0\\.0\\.1:\\d+$`,
			),
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

	// Found by #269, fixed in #271: with the real `fetch` the headers can
	// arrive first, and an abort then fails the body read rather than `fetch`
	// itself. The engine used to read that as "answered something that is not
	// a decision", telling a direct caller of the port the agent answered
	// garbage when it timed out. Aborted once `fetch` has resolved and a task
	// has passed, so the engine is reading a body the agent holds open; on
	// every Node, since nothing here depends on what undici publishes.
	it("rejects with the signal's reason when the deadline passes mid-body, too", async () => {
		const { loaded, headersIn } = await loadedObservingAnswers(agent.origin);
		agent.answer(
			authorizeWith((_request, response) => {
				response.writeHead(200, { "content-type": "application/json", "content-length": 200 });
				response.write('{"decision":"Allow",');
				agent.hold(response);
			}),
		);
		const controller = new AbortController();
		const reason = new Error("rule deadline");
		const failure = loaded.isAuthorized(request(), controller.signal);
		failure.catch(() => undefined);
		// Raced with the call, so a call that fails before its headers arrive
		// fails the case with its own error instead of timing it out.
		await Promise.race([headersIn, failure]);
		await new Promise((resolve) => setTimeout(resolve, 0));
		controller.abort(reason);
		await expect(failure).rejects.toBe(reason);
	});
});

describe("cedarHttpEngine over the wire — redirects", () => {
	// The engine documents that an agent answering non-2xx rejects with
	// CedarEngineError (header "Failure is loud and closed"; README "Failure
	// after boot is a deny"), and it is pointed at one base URL. Until #270 both
	// calls ran with `fetch`'s default `redirect: "follow"`, so a 3xx was never
	// seen: the engine re-POSTed the request's attributes to wherever `Location`
	// named and took that server's answer as the decision — a forbid could come
	// back as an allow. These cases, found by #269 and pinned as `it.fails`
	// until the fix, hold that no redirect is followed.

	it("does not follow a same-origin redirect: a 307 is non-2xx and rejects", async () => {
		const loaded = await loadedAgainst(agent.origin);
		agent.answer((request, response) => {
			if (request.path === "/v1/is_authorized") {
				response.writeHead(307, { location: "/elsewhere/v1/is_authorized" });
				response.end();
			} else {
				cedarAgent(decision("Allow", ["not-the-agent"]))(request, response);
			}
		});
		const failure = loaded.isAuthorized(request(), NEVER_ABORTS);
		await expect(failure).rejects.toThrow(CedarEngineError);
		await expect(failure).rejects.toThrow(/answered 307 to an authorization call/);
		expect(agent.received.map((received) => received.path)).toEqual([
			"/v1/policies",
			"/v1/is_authorized",
		]);
	});

	it("does not follow a cross-origin 307: the other origin receives nothing", async () => {
		// The endpoint rules — https to anything routable, plain http to
		// loopback only — are checked on the configured endpoint alone, so a
		// followed redirect also takes the request past them.
		const loaded = await loadedAgainst(agent.origin, { authentication: "agent-token" });
		stranger.answer(cedarAgent(decision("Allow", ["stranger"])));
		agent.answer(
			authorizeWith((_request, response) => {
				response.writeHead(307, { location: `${stranger.origin}/v1/is_authorized` });
				response.end();
			}),
		);
		const failure = loaded.isAuthorized(request(), NEVER_ABORTS);
		await expect(failure).rejects.toThrow(CedarEngineError);
		await expect(failure).rejects.toThrow(/answered 307 to an authorization call/);
		expect(stranger.received).toEqual([]);
	});

	it("does not follow a cross-origin 302 either — the other origin's answer is not the decision", async () => {
		const loaded = await loadedAgainst(agent.origin);
		// A 302 turns the POST into a GET without a body; the stranger answers
		// whatever the method, and that answer is read as the decision.
		stranger.answer((_request, response) =>
			sendJson(response, 200, decision("Allow", ["stranger"])),
		);
		agent.answer(
			authorizeWith((_request, response) => {
				response.writeHead(302, { location: `${stranger.origin}/v1/is_authorized` });
				response.end();
			}),
		);
		const failure = loaded.isAuthorized(request(), NEVER_ABORTS);
		await expect(failure).rejects.toThrow(CedarEngineError);
		await expect(failure).rejects.toThrow(/answered 302 to an authorization call/);
		expect(stranger.received).toEqual([]);
	});

	it("does not push the policy set to another origin at boot", async () => {
		// Followed, a 307 keeps PUT and its body, so the policy set would land
		// on the other origin and the load would succeed. A 3xx to the load fails
		// boot at once, saying why, and is not retried: the endpoint is
		// configuration, and retrying cannot change where it points.
		agent.answer((_request, response) => {
			response.writeHead(307, { location: `${stranger.origin}/v1/policies` });
			response.end();
		});
		const booting = createCedarHttpEngine({ env: {} }).load(
			policySet(),
			loadContext({ endpoint: agent.origin }),
		);
		await expect(booting).rejects.toThrow(CedarEngineError);
		await expect(booting).rejects.toThrow(
			/answered 307 to the policy load instead of accepting it — redirects are not followed/,
		);
		expect(agent.received).toHaveLength(1);
		expect(stranger.received).toEqual([]);
	});
});

describe("cedarHttpEngine over the wire — boot", () => {
	it("refuses to start naming the endpoint and the refusal when the connection is refused", async () => {
		// One attempt: `retryMs` is not shorter than the deadline, so the first
		// refusal is the last. The retry loop is pinned against a scripted fetch.
		const gone = await FakeCedarAgent.start();
		await gone.stop();
		const load = createCedarHttpEngine({ env: {}, loadTimeoutMs: 1000, retryMs: 1000 }).load(
			policySet(),
			loadContext({ endpoint: gone.origin }),
		);
		await expect(load).rejects.toThrow(CedarEngineError);
		await expect(load).rejects.toThrow(
			new RegExp(
				`cedar engine at ${gone.origin} is unreachable — could not load the policy set from /policies within 1000 ms \\(1 attempts\\): fetch failed: connect ECONNREFUSED 127\\.0\\.0\\.1:\\d+$`,
			),
		);
	});

	it("never calls a refused agent reachable, wherever the deadline falls on its last attempt (#271)", async () => {
		// With room for retries, the last attempt runs under whatever is left of
		// the deadline — a millisecond, when a timer overshoots — and can time
		// out before its refusal arrives. Found by #269: 48 of 200 such loads
		// said "reachable, but the request timed out". It is a race, so this is
		// the check on the real wire, not the pin: before the fix about one load
		// in ten lost it, so twenty in a row caught it about nine runs in ten.
		// `httpEngine.test.mts` pins the same case deterministically. A load
		// whose first attempt times out — a worker stalled past the deadline
		// before the refusal was read — says no answer came, which is also true.
		const gone = await FakeCedarAgent.start();
		await gone.stop();
		const failures: unknown[] = [];
		for (let load = 0; load < 20; load++) {
			try {
				await createCedarHttpEngine({ env: {}, loadTimeoutMs: 50, retryMs: 1 }).load(
					policySet(),
					loadContext({ endpoint: gone.origin }),
				);
				failures.push(new Error("loaded against a closed port"));
			} catch (error) {
				failures.push(error);
			}
		}
		for (const failure of failures) {
			expect(failure).toBeInstanceOf(CedarEngineError);
			const { message } = failure as CedarEngineError;
			expect(message).not.toMatch(/\breachable\b/);
			expect(message).toMatch(
				/(: fetch failed: connect ECONNREFUSED 127\.0\.0\.1:\d+|the request got no response before the deadline: .*)$/,
			);
		}
	});

	it("says no answer came before the deadline when the agent holds the load open", async () => {
		// The agent never answers, so the outcome does not depend on how long
		// the deadline is. A timeout is not evidence the agent is reachable, so
		// the message does not say it is (#271).
		agent.answer((_request, response) => agent.hold(response));
		const load = createCedarHttpEngine({ env: {}, loadTimeoutMs: 100, retryMs: 20 }).load(
			policySet(),
			loadContext({ endpoint: agent.origin }),
		);
		await expect(load).rejects.toThrow(
			/did not accept the policy set from \/policies within 100 ms \(1 attempts\) — the request got no response before the deadline/,
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
			/refused the policy set from \/policies \(400; policies: 10-permit@[0-9a-f]{16}, 20-forbid@[0-9a-f]{16}\): policy 20-forbid: unexpected token/,
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
		agent.answer(cedarAgent(decision("Allow", [pushed("10-permit")])));

		const decided = await evaluate(attrs(), [permit]);
		expect(decided.decision).toBe("allow");
		expect(outcomeOf(decided)).toEqual({
			code: "cedar_deny",
			message: "Denied by Cedar policy",
			passed: true,
			// The agent's reason, as unconfirmed as the revision (#199).
			evaluation: { ...unconfirmed("completed"), determiningPolicies: ["10-permit"] },
		});
		// What was pushed is what the revision was computed over.
		expect(parsed(agent.received[0].body)).toEqual([
			{ id: pushed("10-permit"), content: PERMIT },
			{ id: pushed("20-forbid"), content: FORBID },
		]);
	});

	it("forbids on a determining forbid, reporting the same revisions", async () => {
		const { rule: forbid, logger } = await rule();
		agent.answer(cedarAgent(decision("Deny", [pushed("20-forbid")])));

		const decided = await evaluate(attrs(), [forbid]);
		expect(decided).toMatchObject({ decision: "deny", code: "cedar_deny" });
		expect(outcomeOf(decided)).toEqual(
			expect.objectContaining({
				passed: false,
				evaluation: { ...unconfirmed("completed"), determiningPolicies: ["20-forbid"] },
			}),
		);
		// A forbid is the policies' answer, not a fault.
		expect(logger.error).not.toHaveBeenCalled();
	});

	// maxAnswerBytes travels in the collector's config entry, as endpoint does.
	// A decision over the default bound is a deny under the default and the
	// agent's answer once the entry raises the bound.
	it("reads a decision over the default bound when the entry's maxAnswerBytes allows it", async () => {
		// Large honestly — this load's policy, named again and again — not foreign.
		const ids = Array.from({ length: 40_000 }, () => pushed("10-permit"));
		const large = cedarAgent(decision("Allow", ids));

		const { rule: bounded, logger } = await rule();
		agent.answer(large);
		const refused = await evaluate(attrs(), [bounded]);
		expect(refused.decision).toBe("deny");
		expect(outcomeOf(refused)).toMatchObject({ passed: false, evaluation: unconfirmed("failed") });
		expect(JSON.stringify((logger.error as ReturnType<typeof vi.fn>).mock.calls)).toMatch(
			/more than 1 MiB — refused; set maxAnswerBytes higher/,
		);

		const { rule: raised } = await rule({ maxAnswerBytes: 4 * 1024 * 1024 });
		agent.answer(large);
		const allowed = await evaluate(attrs(), [raised]);
		expect(allowed.decision).toBe("allow");
		expect(outcomeOf(allowed)).toMatchObject({
			passed: true,
			evaluation: unconfirmed("completed"),
		});
	});

	it("does not take an agent's word for the revision — it cannot vouch for what it ran (#244)", async () => {
		const { rule: permit } = await rule();
		agent.answer(
			cedarAgent({ ...decision("Allow", [pushed("10-permit")]), revision: loadedRevision }),
		);
		const decided = await evaluate(attrs(), [permit]);
		expect(outcomeOf(decided).evaluation).toEqual({
			...unconfirmed("completed"),
			determiningPolicies: ["10-permit"],
		});
	});

	it("names the policies an agent reports in a structured form by their file ids (#199)", async () => {
		const { rule: permit } = await rule();
		agent.answer(
			cedarAgent({
				decision: "Allow",
				diagnostics: { reason: [{ policyId: pushed("10-permit") }], errors: [] },
			}),
		);
		const decided = await evaluate(attrs(), [permit]);
		expect(decided.decision).toBe("allow");
		expect(outcomeOf(decided).evaluation).toEqual({
			...unconfirmed("completed"),
			determiningPolicies: ["10-permit"],
		});
	});

	it.each([
		["an unmarked id — a set somebody else pushed", ["10-permit"]],
		["another load's", [agentPolicyId("10-permit", "sha256:0000000000000000")]],
		["an item that is not an id", [42]],
	])("denies, and logs, an allow naming %s (#283)", async (_label, reason) => {
		const { rule: permit, logger } = await rule({ logEvaluationErrors: false });
		agent.answer(cedarAgent({ decision: "Allow", diagnostics: { reason, errors: [] } }));
		const decided = await evaluate(attrs(), [permit]);
		expect(decided.decision).toBe("deny");
		expect(outcomeOf(decided).evaluation).toEqual(unconfirmed("failed"));
		// Never silent: not an evaluation error, a deployment fault.
		expect(JSON.stringify((logger.error as ReturnType<typeof vi.fn>).mock.calls)).toMatch(
			/answered from a policy set this verifier did not load/,
		);
	});

	it.each([true, false])(
		"denies, and logs as a foreign answer, errors alone naming a policy this load never pushed — logEvaluationErrors = %s (#283)",
		async (logEvaluationErrors) => {
			// A set this verifier did not load, answering with errors only: before,
			// logged as this load's evaluation errors — and silenced with them.
			const { rule: permit, logger } = await rule({ logEvaluationErrors });
			agent.answer(
				cedarAgent({
					decision: "Deny",
					diagnostics: {
						reason: [],
						errors: ["error occurred while evaluating policy `10-permit`: no dept"],
					},
				}),
			);
			const decided = await evaluate(attrs(), [permit]);
			expect(decided.decision).toBe("deny");
			expect(outcomeOf(decided).evaluation).toEqual(unconfirmed("failed"));
			const logged = JSON.stringify((logger.error as ReturnType<typeof vi.fn>).mock.calls);
			expect(logged).toMatch(/answered from a policy set this verifier did not load/);
			// Not as this load's evaluation errors, where they are logged at all.
			expect(logged).not.toMatch(/raised errors/);
		},
	);

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

	// See "redirects" above (#269, fixed in #270). Before the fix, through the
	// rule this was a pass: an Allow from a server the deployment never
	// configured decided the request, reported as a completed evaluation.
	it("denies when the agent redirects the call to another origin", async () => {
		const { rule: redirected } = await rule();
		stranger.answer(cedarAgent(decision("Allow", ["stranger"])));
		agent.answer(
			authorizeWith((_request, response) => {
				response.writeHead(307, { location: `${stranger.origin}/v1/is_authorized` });
				response.end();
			}),
		);
		const decided = await evaluate(attrs(), [redirected]);
		expect(decided.decision).toBe("deny");
		expect(outcomeOf(decided)).toMatchObject({ passed: false, evaluation: unconfirmed("failed") });
	});
});
