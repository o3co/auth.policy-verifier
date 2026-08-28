// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Request validation on the decision endpoints (#118).
 *
 * Three things are pinned here, and #125 will pin them again from the outside:
 *
 * 1. Every input a caller controls is bounded by a stated limit — body bytes,
 *    `resource` and `action` length, and the shape of `context` — and each
 *    limit is an operator knob read through `resolveBound` at both boundaries.
 * 2. The body is validated BEFORE the token is verified, so a malformed
 *    unauthenticated request is answered 400 rather than 401.
 * 3. A body-parser failure answers the deny envelope, not Express's HTML page.
 */

import { readFileSync } from "node:fs";
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import {
	type AttributeCollector,
	AttributePipeline,
	type CollectorContext,
	RulePipeline,
	readUntrustedRequestContext,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import {
	DEFAULT_MAX_ACTION_LENGTH,
	DEFAULT_MAX_BODY_BYTES,
	DEFAULT_MAX_CONTEXT_ENTRIES,
	DEFAULT_MAX_CONTEXT_VALUE_LENGTH,
	DEFAULT_MAX_RESOURCE_LENGTH,
} from "#/config/defaults.mjs";
import { HS256KeyResolverFactory } from "#/jwt/index.mjs";
import { createVerifyRouter, type VerifyRouterConfig } from "#/routes/verify.mjs";

/**
 * The deny envelope exactly as `README.md`, `README.ja.md` and `CHANGELOG.md`
 * print it for a body the parser refuses. One literal, checked against the
 * route's own answer and against all three files — see the last describe.
 */
const DOCUMENTED_DENY_ENVELOPE =
	'{"decision": "deny", "code": "invalid_request", "message": "Request body is not valid JSON"}';

/** 64 hex characters — 32 decoded bytes, the entropy floor #114 enforces. */
const JWT_SECRET = "11".repeat(32);
const hs256Key = await HS256KeyResolverFactory({ secret: JWT_SECRET });

const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

async function signToken(payload: Record<string, unknown> = { scope: "read:project" }) {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setExpirationTime("1h")
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.sign(hs256Key.key as import("node:crypto").KeyObject);
}

function createTestApp(overrides: Partial<VerifyRouterConfig> = {}) {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: {
				validate: true,
				key: hs256Key.key,
				algorithms: hs256Key.algorithms,
				issuer: ISSUER,
				audience: AUDIENCE,
				tokenType: "at+jwt",
			},
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			...overrides,
		}),
	);
	return app;
}

const app = createTestApp();

async function post(body: unknown, target = "/verify") {
	const token = await signToken();
	return request(app)
		.post(target)
		.set("Authorization", `Bearer ${token}`)
		.send(body as object);
}

describe("POST /verify — bounded resource and action (#118)", () => {
	it("accepts a resource at exactly the limit", async () => {
		// `a`.repeat(N) is one segment of N type characters — inside the
		// DotNotation grammar, so only the length bound is under test.
		const res = await post({ resource: "a".repeat(DEFAULT_MAX_RESOURCE_LENGTH), action: "read" });
		expect(res.status).not.toBe(400);
	});

	it("returns 400 for a resource one character over the limit", async () => {
		const res = await post({
			resource: "a".repeat(DEFAULT_MAX_RESOURCE_LENGTH + 1),
			action: "read",
		});

		expect(res.status).toBe(400);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain(String(DEFAULT_MAX_RESOURCE_LENGTH));
	});

	it("accepts an action at exactly the limit", async () => {
		const res = await post({
			resource: "project:1",
			action: "r".repeat(DEFAULT_MAX_ACTION_LENGTH),
		});
		expect(res.status).not.toBe(400);
	});

	it("returns 400 for an action one character over the limit", async () => {
		const res = await post({
			resource: "project:1",
			action: "r".repeat(DEFAULT_MAX_ACTION_LENGTH + 1),
		});

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain(String(DEFAULT_MAX_ACTION_LENGTH));
	});

	it("honours a configured resource length", async () => {
		const tight = createTestApp({ maxResourceLength: 8 });
		const token = await signToken();
		const res = await request(tight)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(400);
		expect(res.body.message).toContain("8");
	});
});

describe("POST /verify — whitespace is refused, not trimmed (#118)", () => {
	// The same doctrine `DotNotationResourceParser` applies to `resource`
	// (#117), applied at the schema layer so it also holds for `action` and for
	// a deployment that registered its own parser.
	const whitespace = ["   ", " project:1", "project:1 ", "project\t:1", "project\n:1"];

	for (const resource of whitespace) {
		it(`returns 400 for a resource containing whitespace: ${JSON.stringify(resource)}`, async () => {
			const res = await post({ resource, action: "read" });

			expect(res.status).toBe(400);
			expect(res.body.decision).toBe("deny");
			expect(res.body.code).toBe("invalid_request");
			expect(res.body.message).toContain("whitespace");
		});
	}

	for (const action of ["   ", " read", "read ", "read all"]) {
		it(`returns 400 for an action containing whitespace: ${JSON.stringify(action)}`, async () => {
			const res = await post({ resource: "project:1", action });

			expect(res.status).toBe(400);
			expect(res.body.code).toBe("invalid_request");
			expect(res.body.message).toContain("whitespace");
		});
	}

	it("names the field rather than echoing the value", async () => {
		const res = await post({ resource: "  project:1  ", action: "read" });
		expect(res.body.message).toContain("body.resource");
		expect(res.body.message).not.toContain("project:1");
	});
});

describe("POST /verify — bounded context (#118)", () => {
	it("accepts a context at exactly the entry limit", async () => {
		const context = Object.fromEntries(
			Array.from({ length: DEFAULT_MAX_CONTEXT_ENTRIES }, (_, i) => [`k${i}`, "v"]),
		);
		const res = await post({ resource: "project:1", action: "read", context });
		expect(res.status).not.toBe(400);
	});

	it("returns 400 one entry over the limit", async () => {
		const context = Object.fromEntries(
			Array.from({ length: DEFAULT_MAX_CONTEXT_ENTRIES + 1 }, (_, i) => [`k${i}`, "v"]),
		);
		const res = await post({ resource: "project:1", action: "read", context });

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain(String(DEFAULT_MAX_CONTEXT_ENTRIES));
	});

	it("counts nested properties and array elements, not just top-level keys", async () => {
		// Nesting is a supported shape — `RequestContextAttributeCollector` reads
		// dot paths — so it is counted rather than forbidden. Six entries here:
		// `a`, `b`, `c`, and the three array elements.
		const tight = createTestApp({ maxContextEntries: 5 });
		const token = await signToken();
		const res = await request(tight)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({
				resource: "project:1",
				action: "read",
				context: { a: { b: { c: [1, 2, 3] } } },
			});

		expect(res.status).toBe(400);
		expect(res.body.message).toContain("5");
	});

	it("still admits a nested context inside the bound", async () => {
		const seen: Array<Record<string, unknown> | undefined> = [];
		const recording: AttributeCollector = {
			async collect(context: CollectorContext) {
				seen.push(readUntrustedRequestContext(context.requestContext));
				return new Map();
			},
		};
		const nestedApp = createTestApp({
			attributePipeline: new AttributePipeline([new PayloadScopeCollector(), recording]),
		});
		const token = await signToken();
		const res = await request(nestedApp)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({
				resource: "project:1",
				action: "read",
				context: { tenant: { id: "acme" }, groups: ["a", "b"] },
			});

		expect(res.status).toBe(200);
		expect(seen[0]).toEqual({ tenant: { id: "acme" }, groups: ["a", "b"] });
	});

	it("returns 400 for a context string over the value limit", async () => {
		const res = await post({
			resource: "project:1",
			action: "read",
			context: { blob: "x".repeat(DEFAULT_MAX_CONTEXT_VALUE_LENGTH + 1) },
		});

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain(String(DEFAULT_MAX_CONTEXT_VALUE_LENGTH));
	});

	it("bounds a nested string and a property name the same way", async () => {
		const long = "x".repeat(DEFAULT_MAX_CONTEXT_VALUE_LENGTH + 1);
		const nested = await post({
			resource: "project:1",
			action: "read",
			context: { outer: { inner: long } },
		});
		expect(nested.status).toBe(400);

		const key = await post({
			resource: "project:1",
			action: "read",
			context: { [long]: "v" },
		});
		expect(key.status).toBe(400);
	});
});

describe("POST /verify — unknown properties are refused (#118)", () => {
	/**
	 * The rendering bound `describeUnknownKeys` documents: at most 32 characters
	 * per name, the ellipsis included. Stated here as a literal rather than
	 * imported, so the test fails if the implementation's own constant moves.
	 */
	const MAX_RENDERED_KEY_LENGTH = 32;

	it("truncates a long property name to exactly the documented length", async () => {
		// The error path of a change about explicit limits must not overrun its
		// own stated limit: `slice(0, 32)` plus an ellipsis rendered 33.
		const expected = `${"a".repeat(MAX_RENDERED_KEY_LENGTH - 1)}…`;
		expect(expected).toHaveLength(MAX_RENDERED_KEY_LENGTH);

		const res = await post({
			resource: "project:1",
			action: "read",
			[`a`.repeat(200)]: "v",
		});

		expect(res.status).toBe(400);
		// Quoted through JSON.stringify, so the two quotes sit outside the bound.
		expect(res.body.message).toContain(JSON.stringify(expected));
	});

	it("leaves a name at exactly the limit untruncated", async () => {
		const name = "b".repeat(MAX_RENDERED_KEY_LENGTH);
		const res = await post({ resource: "project:1", action: "read", [name]: "v" });

		expect(res.status).toBe(400);
		expect(res.body.message).toContain(JSON.stringify(name));
		expect(res.body.message).not.toContain('…"');
	});

	it("names at most three unknown properties and says there were more", async () => {
		const res = await post({
			resource: "project:1",
			action: "read",
			one: 1,
			two: 2,
			three: 3,
			four: 4,
		});

		expect(res.status).toBe(400);
		expect(res.body.message).toContain('"one", "two", "three", …');
		expect(res.body.message).not.toContain("four");
	});

	it("returns 400 rather than silently ignoring a body-supplied subject", async () => {
		// Ignoring it left a caller believing it had been honoured. The subject
		// still comes only from the token; refusing is how the caller finds out.
		const res = await post({ resource: "project:1", action: "read", subject: "admin" });

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain("subject");
	});

	it("returns 400 for an unknown property on a batch entry, naming the index", async () => {
		const res = await post(
			{
				decisions: [
					{ resource: "project:1", action: "read" },
					{ resource: "project:2", action: "read", tenant: "acme" },
				],
			},
			"/verify/batch",
		);

		expect(res.status).toBe(400);
		expect(res.body.message).toContain("decisions[1]");
		expect(res.body.message).toContain("tenant");
	});

	it("returns 400 for an unknown property beside decisions", async () => {
		const res = await post(
			{ decisions: [{ resource: "project:1", action: "read" }], parallel: true },
			"/verify/batch",
		);

		expect(res.status).toBe(400);
		expect(res.body.message).toContain("parallel");
	});
});

describe("POST /verify — body validation runs before authentication (#118)", () => {
	/*
	 * BREAKING, and the point of the change: a malformed body is answered 400
	 * whether or not a token was presented. Verifying the token first let an
	 * unauthenticated caller drive the expensive half of the request — an
	 * attacker-chosen `kid` can send the RS256 path to the network, and an
	 * HS256 rotation tries every configured secret — on a body that was never
	 * usable. What runs first now is bounded by the limits above.
	 */

	it("answers 400 for a malformed body with no token at all", async () => {
		const res = await request(app).post("/verify").send({ resource: "project:1" });

		expect(res.status).toBe(400);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("invalid_request");
	});

	it("answers 400 for a malformed body with a token that would not verify", async () => {
		const res = await request(app)
			.post("/verify")
			.set("Authorization", "Bearer not.a.token")
			.send({ resource: "  ", action: "read" });

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("still answers 401 when the body is well-formed and the token is not", async () => {
		const res = await request(app)
			.post("/verify")
			.set("Authorization", "Bearer not.a.token")
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("still answers 401 for a well-formed body with no token", async () => {
		const res = await request(app).post("/verify").send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("missing_token");
	});

	it("answers 400 for a malformed batch with no token", async () => {
		const res = await request(app).post("/verify/batch").send({ decisions: [] });

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("never runs the pipelines for a request refused on its body", async () => {
		let collected = 0;
		const counting: AttributeCollector = {
			async collect() {
				collected += 1;
				return new Map();
			},
		};
		const countingApp = createTestApp({
			attributePipeline: new AttributePipeline([counting]),
		});

		await request(countingApp).post("/verify").send({ resource: "project:1" });
		expect(collected).toBe(0);
	});
});

describe("POST /verify — body-parser failures answer the deny envelope (#118, #126 item 6)", () => {
	it("answers 400 invalid_request for malformed JSON, not Express's HTML page", async () => {
		const token = await signToken();
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set("Content-Type", "application/json")
			.send('{"resource": "project:1", ');

		expect(res.status).toBe(400);
		expect(res.type).toBe("application/json");
		expect(res.body).toEqual(JSON.parse(DOCUMENTED_DENY_ENVELOPE));
	});

	it("answers 413 payload_too_large for a body over the byte limit", async () => {
		const token = await signToken();
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set("Content-Type", "application/json")
			.send(
				JSON.stringify({
					resource: "project:1",
					action: "read",
					context: { blob: "x".repeat(DEFAULT_MAX_BODY_BYTES) },
				}),
			);

		expect(res.status).toBe(413);
		expect(res.type).toBe("application/json");
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("payload_too_large");
	});

	it("honours a configured body limit", async () => {
		const tight = createTestApp({ maxBodyBytes: 128 });
		const token = await signToken();
		const res = await request(tight)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set("Content-Type", "application/json")
			.send(
				JSON.stringify({ resource: "project:1", action: "read", context: { b: "x".repeat(200) } }),
			);

		expect(res.status).toBe(413);
		expect(res.body.code).toBe("payload_too_large");
	});

	it("answers 415 unsupported_media_type for an unreadable charset", async () => {
		const token = await signToken();
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set("Content-Type", "application/json; charset=iso-8859-1")
			.send('{"resource":"project:1","action":"read"}');

		expect(res.status).toBe(415);
		expect(res.type).toBe("application/json");
		expect(res.body.code).toBe("unsupported_media_type");
	});

	it("answers the deny envelope for a body sent as text/plain", async () => {
		// `express.json` skips a non-JSON content type, so the body never
		// becomes an object — a malformed request, answered as one.
		const token = await signToken();
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set("Content-Type", "text/plain")
			.send("resource=project:1");

		expect(res.status).toBe(400);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("invalid_request");
	});

	it("never echoes the offending body back to the caller", async () => {
		const res = await request(app)
			.post("/verify")
			.set("Content-Type", "application/json")
			.send('{"totally-secret-key": ');

		expect(JSON.stringify(res.body)).not.toContain("totally-secret-key");
	});
});

describe("the documented deny envelope is the one the endpoint emits (#118, #125)", () => {
	/*
	 * The envelope is a BREAKING wire-contract change, and these three files are
	 * what a client author implements against — the first version of this prose
	 * carried `{"decision": "deny", "code", "message"}`, which is not JSON at
	 * all. Three hand-written copies of a shape is the drift this repo has been
	 * bitten by before, so the copies are pinned here rather than trusted: one
	 * literal, asserted to be valid JSON, to equal what the route actually
	 * answers, and to appear verbatim in every file that documents it.
	 *
	 * #125 will pin the same contract from outside the repo. Both should be
	 * describing this object.
	 */
	const documentedIn = ["README.md", "README.ja.md", "CHANGELOG.md"] as const;

	/** Repo root, four levels up from `packages/server/src/__tests__`. */
	const repoRoot = new URL("../../../../", import.meta.url);

	it("is valid JSON", () => {
		expect(() => JSON.parse(DOCUMENTED_DENY_ENVELOPE)).not.toThrow();
		expect(JSON.parse(DOCUMENTED_DENY_ENVELOPE)).toEqual({
			decision: "deny",
			code: "invalid_request",
			message: "Request body is not valid JSON",
		});
	});

	it.each(documentedIn)("appears verbatim in %s", (file) => {
		const content = readFileSync(new URL(file, repoRoot), "utf8");
		expect(content).toContain(DOCUMENTED_DENY_ENVELOPE);
	});

	it("carries no stale copy of the malformed shape", () => {
		for (const file of documentedIn) {
			const content = readFileSync(new URL(file, repoRoot), "utf8");
			expect(content).not.toContain('"code", "message"');
		}
	});

	/*
	 * The other half of the same drift: the READMEs print a `verify { … }` HOCON
	 * block, and a default stated there that the code does not apply is a
	 * config example that lies. The shipped `templates/standalone/config/
	 * application.conf` is already parsed and asserted by that package's
	 * `loadConfig` tests, so pinning the READMEs here closes the chain
	 * docs → shipped config → code.
	 *
	 * A regex rather than a HOCON parse: `packages/server` has no HOCON
	 * dependency and should not grow one to check prose, and the shape at risk
	 * is the number, not the syntax.
	 */
	const documentedDefaults = [
		["maxBodyBytes", DEFAULT_MAX_BODY_BYTES],
		["maxResourceLength", DEFAULT_MAX_RESOURCE_LENGTH],
		["maxActionLength", DEFAULT_MAX_ACTION_LENGTH],
		["maxContextEntries", DEFAULT_MAX_CONTEXT_ENTRIES],
		["maxContextValueLength", DEFAULT_MAX_CONTEXT_VALUE_LENGTH],
	] as const;

	it.each(["README.md", "README.ja.md"])("states this package's defaults in %s", (file) => {
		const content = readFileSync(new URL(file, repoRoot), "utf8");
		for (const [key, value] of documentedDefaults) {
			expect(content).toMatch(new RegExp(`^\\s*${key} = ${value}\\s*(#|$)`, "m"));
		}
	});
});

describe("createVerifyRouter — the input limits at both boundaries (#118, #157)", () => {
	// Each new limit is a numeric knob, so it goes through `resolveBound` at the
	// router and through `boundedNumber` in the schema — one reader, one wording.
	// See AGENTS.md, "Two-Boundary Config Validation".
	const knobs = [
		"maxBodyBytes",
		"maxResourceLength",
		"maxActionLength",
		"maxContextEntries",
		"maxContextValueLength",
	] as const;

	const refusal = (act: () => unknown): string | undefined => {
		try {
			act();
			return undefined;
		} catch (cause) {
			return (cause as Error).message;
		}
	};

	const routerRefusal = (knob: string, value: unknown) =>
		refusal(() => createTestApp({ [knob]: value } as Partial<VerifyRouterConfig>));

	const schemaRefusal = (knob: string, value: unknown): string | undefined => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					algorithm: "HS256",
					secret: JWT_SECRET,
					mode: "verify",
					issuer: ISSUER,
					audience: AUDIENCE,
				},
			},
			attribute: { collectors: [] },
			rule: { collectors: [] },
			verify: { [knob]: value },
		});
		return result.success
			? undefined
			: result.error.issues.find((issue) => issue.path.at(-1) === knob)?.message;
	};

	for (const knob of knobs) {
		it.each([
			["zero", 0],
			["a negative value", -1],
			["a fractional value", 1.5],
			["true", true],
			["null", null],
			["an empty string", ""],
			["a non-numeric string", "abc"],
		])(`refuses ${knob} = %s in the schema's wording`, (_label, value) => {
			const fromRouter = routerRefusal(knob, value);
			expect(fromRouter).toBeDefined();
			expect(schemaRefusal(knob, value)).toBe(fromRouter);
		});

		it(`takes the string form for ${knob}`, () => {
			expect(routerRefusal(knob, "16")).toBeUndefined();
		});
	}

	it("defaults every limit when the block is absent", () => {
		const parsed = AppConfigSchema.parse({
			oauth: {
				jwt: {
					algorithm: "HS256",
					secret: JWT_SECRET,
					mode: "verify",
					issuer: ISSUER,
					audience: AUDIENCE,
				},
			},
			attribute: { collectors: [] },
			rule: { collectors: [] },
		});

		expect(parsed.verify).toMatchObject({
			maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
			maxResourceLength: DEFAULT_MAX_RESOURCE_LENGTH,
			maxActionLength: DEFAULT_MAX_ACTION_LENGTH,
			maxContextEntries: DEFAULT_MAX_CONTEXT_ENTRIES,
			maxContextValueLength: DEFAULT_MAX_CONTEXT_VALUE_LENGTH,
		});
	});
});
