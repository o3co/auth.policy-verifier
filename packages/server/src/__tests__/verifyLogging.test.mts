// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Failure-path observability for the verify router (#107).
 *
 * Before these tests the service logged nothing on any failure path: a JWKS
 * outage was returned as the same bare `401 invalid_token` as a garbage token,
 * and every pipeline error became a `500` with the cause discarded. The router
 * now emits one structured event per failure through an injected `EventLogger`:
 *
 *   - `jwt_token_rejected`            (warn)  — the token itself failed
 *     verification: bad signature, expired, claim mismatch, malformed.
 *   - `jwt_verification_unavailable`  (error) — verification could not be
 *     attempted/completed for reasons unrelated to the token: JWKS fetch
 *     timeout or any non-jose infrastructure error.
 *   - `verify_internal_error`         (error) — a collector/parser/pipeline
 *     error swallowed into a 500; carries the discarded cause.
 *
 * The wire contract is unchanged: callers still see 401/500. What changes is
 * that the operator can now tell the three situations apart from the log.
 */
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import {
	AttributePipeline,
	type EventLogger,
	type Rule,
	type RuleCollector,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { errors, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { HS256KeyResolverFactory } from "#/jwt/index.mjs";
import { createVerifyRouter, type VerifyRouterJwtConfig } from "#/routes/verify.mjs";

const JWT_SECRET = "test-secret";
const hs256Key = await HS256KeyResolverFactory({ secret: JWT_SECRET });
const wrongKey = await HS256KeyResolverFactory({ secret: "a-different-secret" });

const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

interface CapturedEvent {
	level: "warn" | "error";
	obj: Record<string, unknown>;
	msg: string;
}

/** EventLogger implementation that records every call for assertion. */
function captureEvents(): { events: CapturedEvent[]; logger: EventLogger } {
	const events: CapturedEvent[] = [];
	return {
		events,
		logger: {
			warn(obj, msg) {
				events.push({ level: "warn", obj, msg });
			},
			error(obj, msg) {
				events.push({ level: "error", obj, msg });
			},
		},
	};
}

interface SignOptions {
	key?: unknown;
	expiresAt?: number;
}

async function signToken(payload: Record<string, unknown>, options: SignOptions = {}) {
	const jwt = new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE);
	if (options.expiresAt !== undefined) {
		jwt.setExpirationTime(options.expiresAt);
	}
	return jwt.sign((options.key ?? hs256Key.key) as import("node:crypto").KeyObject);
}

const verifyingJwt: VerifyRouterJwtConfig = {
	validate: true,
	key: hs256Key.key,
	algorithms: hs256Key.algorithms,
	issuer: ISSUER,
	audience: AUDIENCE,
	tokenType: "at+jwt",
};

function createTestApp(overrides: {
	jwt?: VerifyRouterJwtConfig;
	logger?: EventLogger;
	ruleCollectors?: RuleCollector[];
}) {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: overrides.jwt ?? verifyingJwt,
			logger: overrides.logger,
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
			rulePipeline: new RulePipeline(
				overrides.ruleCollectors ?? [new ResourceActionScopeRuleCollector()],
			),
		}),
	);
	return app;
}

const throwingRuleCollector: RuleCollector = {
	collect(): Promise<Rule[]> {
		return Promise.reject(new Error("rule store exploded"));
	},
};

describe("verify router failure logging: token rejections (warn)", () => {
	it("logs jwt_token_rejected with the jose error for an expired token, still 401", async () => {
		const { events, logger } = captureEvents();
		const app = createTestApp({ logger });
		const token = await signToken(
			{ scope: "read:project" },
			{ expiresAt: Math.floor(Date.now() / 1000) - 3600 },
		);

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ level: "warn", msg: "jwt_token_rejected" });
		expect((events[0].obj.err as { code?: string }).code).toBe("ERR_JWT_EXPIRED");
	});

	it("logs jwt_token_rejected for a bad signature", async () => {
		const { events, logger } = captureEvents();
		const app = createTestApp({ logger });
		const token = await signToken({ scope: "read:project" }, { key: wrongKey.key });

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(401);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ level: "warn", msg: "jwt_token_rejected" });
		expect((events[0].obj.err as { code?: string }).code).toBe(
			"ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
		);
	});

	it("logs jwt_token_rejected for a malformed token on the decode-only path", async () => {
		const { events, logger } = captureEvents();
		const app = createTestApp({ jwt: { validate: false }, logger });

		const res = await request(app)
			.post("/verify")
			.set("Authorization", "Bearer not-a-jwt")
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(401);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ level: "warn", msg: "jwt_token_rejected" });
	});
});

describe("verify router failure logging: verification unavailable (error)", () => {
	it("logs jwt_verification_unavailable when the JWKS lookup times out, distinct from a bad token", async () => {
		const { events, logger } = captureEvents();
		// A remote-JWKS deployment passes a get-key function; jose surfaces a
		// fetch timeout as JWKSTimeout out of jwtVerify.
		const app = createTestApp({
			jwt: {
				...verifyingJwt,
				key: async () => {
					throw new errors.JWKSTimeout();
				},
			},
			logger,
		});
		const token = await signToken({ scope: "read:project" });

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		// The caller still cannot be authenticated — the wire contract stays 401.
		expect(res.status).toBe(401);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ level: "error", msg: "jwt_verification_unavailable" });
		expect(events[0].obj.err).toBeInstanceOf(errors.JWKSTimeout);
	});

	it("logs jwt_verification_unavailable for a non-jose infrastructure error", async () => {
		const { events, logger } = captureEvents();
		const app = createTestApp({
			jwt: {
				...verifyingJwt,
				key: async () => {
					throw new TypeError("fetch failed");
				},
			},
			logger,
		});
		const token = await signToken({ scope: "read:project" });

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(401);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ level: "error", msg: "jwt_verification_unavailable" });
		expect(events[0].obj.err).toBeInstanceOf(TypeError);
	});
});

describe("verify router failure logging: internal errors (error)", () => {
	it("logs verify_internal_error with the swallowed cause on POST /verify", async () => {
		const { events, logger } = captureEvents();
		const app = createTestApp({ logger, ruleCollectors: [throwingRuleCollector] });
		const token = await signToken({ scope: "read:project" });

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(500);
		expect(res.body.code).toBe("internal_error");
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			level: "error",
			msg: "verify_internal_error",
			obj: { endpoint: "/verify" },
		});
		expect((events[0].obj.err as Error).message).toBe("rule store exploded");
	});

	it("logs verify_internal_error with endpoint /verify/batch on the batch route", async () => {
		const { events, logger } = captureEvents();
		const app = createTestApp({ logger, ruleCollectors: [throwingRuleCollector] });
		const token = await signToken({ scope: "read:project" });

		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({ decisions: [{ resource: "project", action: "read" }] });

		expect(res.status).toBe(500);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			level: "error",
			msg: "verify_internal_error",
			obj: { endpoint: "/verify/batch" },
		});
		expect((events[0].obj.err as Error).message).toBe("rule store exploded");
	});
});

describe("verify router failure logging: default sink and quiet paths", () => {
	it("falls back to the console-backed logger when none is injected", async () => {
		const spy = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			const app = createTestApp({ ruleCollectors: [throwingRuleCollector] });
			const token = await signToken({ scope: "read:project" });

			const res = await request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${token}`)
				.send({ resource: "project", action: "read" });

			expect(res.status).toBe(500);
			expect(spy).toHaveBeenCalledWith(
				expect.objectContaining({ endpoint: "/verify", err: expect.any(Error) }),
				"verify_internal_error",
			);
		} finally {
			spy.mockRestore();
		}
	});

	it("logs nothing on an allowed request", async () => {
		const { events, logger } = captureEvents();
		const app = createTestApp({ logger });
		const token = await signToken({ scope: "read:project" });

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(200);
		expect(events).toHaveLength(0);
	});

	it("logs nothing for a request that never presented a token", async () => {
		// Absent/garbled Authorization headers are plain client errors: no
		// verification was attempted, so there is nothing to distinguish.
		const { events, logger } = captureEvents();
		const app = createTestApp({ logger });

		const missing = await request(app)
			.post("/verify")
			.send({ resource: "project", action: "read" });
		const badScheme = await request(app)
			.post("/verify")
			.set("Authorization", "Basic dXNlcjpwdw==")
			.send({ resource: "project", action: "read" });

		expect(missing.status).toBe(401);
		expect(badScheme.status).toBe(401);
		expect(events).toHaveLength(0);
	});
});
