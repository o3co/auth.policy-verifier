// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Logger, Module } from "@o3co/auth.policy-verifier.core";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
	AppConfigSchema,
	builtinKeyResolversModule,
	createApp,
	JWT_MODE_MIGRATION_MESSAGE,
} from "#/index.mjs";

const JWT_SECRET = "test-secret";
const secretKey = new TextEncoder().encode(JWT_SECRET);
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

async function signToken(payload: Record<string, unknown>): Promise<string> {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.sign(secretKey);
}

// Minimal test module that registers factories for a scope collector and rule collector
const testModule: Module = {
	name: "test-module",
	async init(context) {
		context.attributeCollectorRegistry.register("TestScopeCollector", () => ({
			async collect(ctx) {
				const scopes = ((ctx.payload.scope as string) ?? "").split(" ");
				return new Map([["scopes", scopes]]);
			},
		}));
		context.ruleCollectorRegistry.register("TestScopeRuleCollector", () => ({
			async collect(ctx) {
				return [
					{
						ruleType: "scope",
						code: "invalid_scope",
						message: "Insufficient scope",
						verify(attributes) {
							const scopes = (attributes.get("scopes") as string[]) ?? [];
							return scopes.includes(`${ctx.action}:${ctx.resource.resourceType}`);
						},
					},
				];
			},
		}));
		context.ruleCollectorRegistry.register("EmptyRuleCollector", () => ({
			async collect() {
				return [];
			},
		}));
		context.resourceParserRegistry.register("SimpleParser", () => ({
			parse(raw: string) {
				return { raw, resourceType: raw, resourceId: undefined };
			},
		}));
	},
};

const testConfig = AppConfigSchema.parse({
	oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
	attribute: { collectors: [{ collector: "TestScopeCollector" }] },
	rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
	resource: { parser: "SimpleParser" },
});

describe("createApp", () => {
	it("creates an Express app that allows valid requests", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: testConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("denies requests with insufficient scope", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: testConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "write:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
	});

	it("throws if config references unregistered collector", async () => {
		const badConfig = AppConfigSchema.parse({
			oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
			attribute: { collectors: [{ collector: "NonExistent" }] },
			rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
		});

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: badConfig,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow('Registry: "NonExistent" is not registered');
	});

	it("throws when a hand-built verify-mode config omits issuer/audience", async () => {
		// AppConfigSchema rejects this shape, so reach createApp with an object that
		// never went through it — the same path a library consumer can take.
		const handBuilt = {
			...testConfig,
			oauth: { jwt: { ...testConfig.oauth.jwt, issuer: undefined, audience: undefined } },
		} as unknown as typeof testConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/createApp: oauth\.jwt\.issuer is required/);
	});

	// The next two shapes slipped past the pre-#132 createApp check (a bare falsy
	// test that accepted empty arrays and never looked at tokenType) and only
	// failed one call later, inside the router. The shared guard now rejects
	// them at this boundary, naming the oauth.jwt.* key the operator wrote.
	it("throws when a hand-built config pins issuer to an empty array", async () => {
		const handBuilt = {
			...testConfig,
			oauth: { jwt: { ...testConfig.oauth.jwt, issuer: [] } },
		} as unknown as typeof testConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/createApp: oauth\.jwt\.issuer is required/);
	});

	it("throws when a hand-built config omits tokenType", async () => {
		const handBuilt = {
			...testConfig,
			oauth: { jwt: { ...testConfig.oauth.jwt, tokenType: undefined } },
		} as unknown as typeof testConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/createApp: oauth\.jwt\.tokenType is required/);
	});

	it("refuses to boot a hand-built config with a plaintext JWKS URI (#109)", async () => {
		// AppConfigSchema rejects this at config-parse time, but a library consumer
		// can hand-build the config; boot is then the last place to catch a key
		// source anyone on the network path can substitute. It must fail here and
		// not at the first request that misses the key cache.
		const handBuilt = {
			...testConfig,
			oauth: {
				jwt: {
					...testConfig.oauth.jwt,
					algorithm: "RS256",
					secret: undefined,
					jwksUri: "http://auth-provider:3000/.well-known/jwks.json",
				},
			},
		} as unknown as typeof testConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/jwksUri must use https/);
	});

	it('defaults a hand-built config with no mode to verify, and its errors name oauth.jwt.mode = "verify"', async () => {
		// A consumer that omits `mode` gets the schema's default (verify) at this
		// boundary too, and the guard's message names the wire key the operator
		// would have to write — not the internal `validate` discriminant (#134).
		const { mode: _mode, ...noMode } = testConfig.oauth.jwt;
		const handBuilt = {
			...testConfig,
			oauth: { jwt: { ...noMode, issuer: undefined } },
		} as unknown as typeof testConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(
			/createApp: oauth\.jwt\.issuer is required when oauth\.jwt\.mode is "verify"/,
		);
	});

	it("rejects a token minted for another audience end to end", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: testConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuedAt()
			.setIssuer(ISSUER)
			.setAudience("https://other-service.test")
			.sign(secretKey);

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("includes healthcheck endpoint", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: testConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const res = await request(app).get("/healthcheck");
		expect(res.status).toBe(200);
	});

	it("starts successfully and decodes tokens in insecure-decode mode with no key material", async () => {
		// mode="insecure-decode" + no key material must not throw at startup
		const noKeyConfig = AppConfigSchema.parse({
			oauth: { jwt: { mode: "insecure-decode" } },
			attribute: { collectors: [{ collector: "TestScopeCollector" }] },
			rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
			resource: { parser: "SimpleParser" },
		});

		const app = await createApp({
			pathResolver: (s: string) => s,
			config: noKeyConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		// Token is decoded (not verified) — use the same secret but validation is skipped
		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("throws when no rule collector is configured", async () => {
		const noRuleConfig = AppConfigSchema.parse({
			oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
			attribute: { collectors: [{ collector: "TestScopeCollector" }] },
			rule: { collectors: [] },
			resource: { parser: "SimpleParser" },
		});

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: noRuleConfig,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/at least one rule collector/);
	});

	it("denies with no_applicable_rule when the pipeline collects no rules", async () => {
		const emptyRuleConfig = AppConfigSchema.parse({
			oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
			attribute: { collectors: [{ collector: "TestScopeCollector" }] },
			rule: { collectors: [{ collector: "EmptyRuleCollector" }] },
			resource: { parser: "SimpleParser" },
		});

		const app = await createApp({
			pathResolver: (s: string) => s,
			config: emptyRuleConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body).toMatchObject({
			decision: "deny",
			code: "no_applicable_rule",
			message: "No applicable rule was collected for this request",
		});
		expect(res.body.reason.groups).toEqual([]);
	});

	it("allows an empty rule set only when the deployment opts into onEmptyRuleSet=allow", async () => {
		const failOpenConfig = AppConfigSchema.parse({
			oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
			attribute: { collectors: [{ collector: "TestScopeCollector" }] },
			rule: { collectors: [{ collector: "EmptyRuleCollector" }], onEmptyRuleSet: "allow" },
			resource: { parser: "SimpleParser" },
		});

		const app = await createApp({
			pathResolver: (s: string) => s,
			config: failOpenConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});
});

describe("createApp logging (#107)", () => {
	interface CapturedCall {
		level: "trace" | "debug" | "info" | "warn" | "error" | "fatal";
		obj: Record<string, unknown> | string;
		msg?: string;
	}

	/** Full `Logger` implementation that records every call for assertion. */
	function captureLogger(): { calls: CapturedCall[]; logger: Logger } {
		const calls: CapturedCall[] = [];
		const record =
			(level: CapturedCall["level"]) =>
			(obj: Record<string, unknown> | string, msg?: string): void => {
				calls.push({ level, obj, msg });
			};
		const logger: Logger = {
			trace: record("trace"),
			debug: record("debug"),
			info: record("info"),
			warn: record("warn"),
			error: record("error"),
			fatal: record("fatal"),
			child: () => logger,
		};
		return { calls, logger };
	}

	const noKeyConfig = AppConfigSchema.parse({
		oauth: { jwt: { mode: "insecure-decode" } },
		attribute: { collectors: [{ collector: "TestScopeCollector" }] },
		rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
		resource: { parser: "SimpleParser" },
	});

	it("routes the insecure-decode event through the injected logger, not the console", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			const { calls, logger } = captureLogger();
			await createApp({
				pathResolver: (s: string) => s,
				config: noKeyConfig,
				modules: [testModule, builtinKeyResolversModule],
				logger,
			});

			const events = calls.filter((c) => c.msg === "jwt_validation_disabled");
			expect(events).toHaveLength(1);
			expect(consoleSpy).not.toHaveBeenCalled();
		} finally {
			consoleSpy.mockRestore();
		}
	});

	it("emits the insecure-decode event on the console-backed default when no logger is injected", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			await createApp({
				pathResolver: (s: string) => s,
				config: noKeyConfig,
				modules: [testModule, builtinKeyResolversModule],
			});
			expect(consoleSpy).toHaveBeenCalledWith(expect.any(Object), "jwt_validation_disabled");
		} finally {
			consoleSpy.mockRestore();
		}
	});

	it("honours logging.level for the console-backed default logger", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			const silentConfig = AppConfigSchema.parse({
				oauth: { jwt: { mode: "insecure-decode" } },
				logging: { level: "silent" },
				attribute: { collectors: [{ collector: "TestScopeCollector" }] },
				rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
				resource: { parser: "SimpleParser" },
			});
			await createApp({
				pathResolver: (s: string) => s,
				config: silentConfig,
				modules: [testModule, builtinKeyResolversModule],
			});
			expect(consoleSpy).not.toHaveBeenCalled();
		} finally {
			consoleSpy.mockRestore();
		}
	});

	it("hands the logger to the verify router so request failures reach the same sink", async () => {
		const { calls, logger } = captureLogger();
		const failingModule: Module = {
			name: "failing-module",
			async init(context) {
				context.ruleCollectorRegistry.register("FailingRuleCollector", () => ({
					collect() {
						return Promise.reject(new Error("rule store exploded"));
					},
				}));
			},
		};
		const failingConfig = AppConfigSchema.parse({
			oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
			attribute: { collectors: [{ collector: "TestScopeCollector" }] },
			rule: { collectors: [{ collector: "FailingRuleCollector" }] },
			resource: { parser: "SimpleParser" },
		});
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: failingConfig,
			modules: [testModule, failingModule, builtinKeyResolversModule],
			logger,
		});

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(500);
		const errors = calls.filter((c) => c.level === "error");
		expect(errors).toHaveLength(1);
		expect(errors[0].msg).toBe("verify_internal_error");
	});
});

describe("createApp insecure decode mode (#106, #134)", () => {
	const ackConfig = AppConfigSchema.parse({
		oauth: { jwt: { mode: "insecure-decode" } },
		attribute: { collectors: [{ collector: "TestScopeCollector" }] },
		rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
		resource: { parser: "SimpleParser" },
	});

	it("refuses to boot a hand-built config still carrying the removed wire keys", async () => {
		// AppConfigSchema rejects this shape, so reach createApp with an object
		// that never went through it — the same path a library consumer can take.
		// The old pair must not be silently reinterpreted (defaulted mode would
		// mean verify, and the operator asked for decode): fail with migration help.
		const handBuilt = {
			...ackConfig,
			oauth: { jwt: { validate: false, allowInsecureDecode: true } },
		} as unknown as typeof ackConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(JWT_MODE_MIGRATION_MESSAGE);
	});

	// A JS consumer can hand createApp anything. The stale-key and mode checks
	// below reach into the block with `in` and object spread, both of which
	// throw a bare TypeError on a primitive — so the shape is verified first and
	// reported like every other boundary error, naming the config path.
	it.each([
		["null", null],
		["undefined", undefined],
		["a string", "verify"],
		["a number", 1],
		["a boolean", true],
		["an array", []],
	])("refuses to boot when oauth.jwt is %s", async (_label, jwtValue) => {
		const handBuilt = {
			...ackConfig,
			oauth: { jwt: jwtValue },
		} as unknown as typeof ackConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/^createApp: oauth\.jwt must be a config object/);
	});

	it("refuses to boot when the whole oauth block is malformed", async () => {
		const handBuilt = { ...ackConfig, oauth: null } as unknown as typeof ackConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/^createApp: oauth must be a config object/);
	});

	it("does not report a TypeError for a malformed oauth.jwt", async () => {
		// The regression this guards: `"validate" in jwtWire` throws
		// "Cannot use 'in' operator..." before any of our validation runs.
		const handBuilt = { ...ackConfig, oauth: { jwt: null } } as unknown as typeof ackConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.not.toBeInstanceOf(TypeError);
	});

	it("refuses to boot a hand-built config with an unknown mode value", async () => {
		// "insecure-decode" is the consent string; anything else must not fall
		// through to either path.
		const handBuilt = {
			...ackConfig,
			oauth: { jwt: { mode: "decode" } },
		} as unknown as typeof ackConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/oauth\.jwt\.mode must be "verify" or "insecure-decode"/);
	});

	it("boots insecure-decode mode and emits jwt_validation_disabled at error level", async () => {
		const calls: Array<{ level: string; msg?: string }> = [];
		const record =
			(level: string) =>
			(_obj: Record<string, unknown> | string, msg?: string): void => {
				calls.push({ level, msg });
			};
		const logger: Logger = {
			trace: record("trace"),
			debug: record("debug"),
			info: record("info"),
			warn: record("warn"),
			error: record("error"),
			fatal: record("fatal"),
			child: () => logger,
		};

		const app = await createApp({
			pathResolver: (s: string) => s,
			config: ackConfig,
			modules: [testModule, builtinKeyResolversModule],
			logger,
		});

		// A mis-set env var disabling all verification is an operator-facing
		// incident, not a curiosity: error, so a level=error fleet still sees it.
		expect(calls).toContainEqual({ level: "error", msg: "jwt_validation_disabled" });
		expect(calls.filter((c) => c.msg === "jwt_validation_disabled")).toHaveLength(1);

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });
		expect(res.status).toBe(200);
	});
});
