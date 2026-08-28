// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes, Logger, Module, Rule } from "@o3co/auth.policy-verifier.core";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
// `JWT_MODE_REMOVED_KEYS` is deliberately not re-exported from the package
// index: the removed-key list is how the two boundaries agree with each other,
// not something a consumer configures against (the migration *message* is the
// consumer-facing half, and that one is public).
import { JWT_MODE_REMOVED_KEYS } from "#/config/application.schema.mjs";
import {
	AppConfigSchema,
	builtinKeyResolversModule,
	createApp,
	JWT_MODE_MIGRATION_MESSAGE,
} from "#/index.mjs";

/** 64 hex characters — 32 decoded bytes, the entropy floor #114 enforces. */
const JWT_SECRET = "11".repeat(32);
const secretKey = new TextEncoder().encode(JWT_SECRET);
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

async function signToken(payload: Record<string, unknown>): Promise<string> {
	return (
		new SignJWT(payload)
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuedAt()
			// iat and exp are both mandatory now (#110).
			.setExpirationTime("1h")
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.sign(secretKey)
	);
}

// Minimal test module that registers factories for a scope collector and rule collector
const testModule: Module = {
	name: "test-module",
	async init(context) {
		context.attributeCollectorRegistry.register("TestScopeCollector", () => ({
			async collect(ctx) {
				const scopes = ((ctx.subject.scope as string) ?? "").split(" ");
				return new Map([["scopes", scopes]]);
			},
		}));
		context.ruleCollectorRegistry.register("TestScopeRuleCollector", () => ({
			async collect(ctx) {
				// The required scope is fixed HERE, at collect time, and copied into
				// the rule as a plain string — the same shape the real
				// `ResourceActionScopeRuleCollector` uses to build its `HasScope`.
				//
				// The contract (AGENTS.md, Collector / Rule / Attribute) draws its line
				// between the two things that look alike: fixing *what the rule looks
				// for* while the request is in hand is fine, because `verify` stays a
				// function of `attrs` alone. Keeping `ctx` and reading it inside
				// `verify` is not — the answer would then depend on request state the
				// evaluator cannot see, which is what breaks isolation testing,
				// caching, and `evaluate()`'s licence to run every rule group.
				//
				// This file is where the violating copy in `metrics.test.mts` was
				// copied from (#150, #152), so it is written to be copied again.
				const requiredScope = `${ctx.action}:${ctx.resource.resourceType}`;
				return [
					{
						ruleType: "scope",
						code: "invalid_scope",
						message: `Insufficient scope: ${requiredScope} is required`,
						verify(attributes) {
							// Safe-deny: a missing or malformed attribute denies, never throws.
							const scopes = attributes.get("scopes");
							return Array.isArray(scopes) && scopes.includes(requiredScope);
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
			.setExpirationTime("1h")
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

	// Driven off the same exported list the schema is checked against (#158), so
	// the two boundaries cannot end up refusing different sets of removed keys:
	// a key added to the constant is asserted here and in the schema suite alike.
	it.each([...JWT_MODE_REMOVED_KEYS])(
		"refuses to boot a hand-built config carrying the removed key %s on its own",
		async (staleKey) => {
			const handBuilt = {
				...ackConfig,
				oauth: { jwt: { [staleKey]: true } },
			} as unknown as typeof ackConfig;

			await expect(
				createApp({
					pathResolver: (s: string) => s,
					config: handBuilt,
					modules: [testModule, builtinKeyResolversModule],
				}),
			).rejects.toThrow(JWT_MODE_MIGRATION_MESSAGE);
		},
	);

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

describe("createApp caller authentication (#108)", () => {
	interface Captured {
		level: "trace" | "debug" | "info" | "warn" | "error" | "fatal";
		obj: Record<string, unknown> | string;
		msg?: string;
	}

	function captureLogger(): { calls: Captured[]; logger: Logger } {
		const calls: Captured[] = [];
		const record =
			(level: Captured["level"]) =>
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

	/** The shared testConfig plus an `http` block, parsed through the schema. */
	function configWithHttp(http: Record<string, unknown>) {
		return AppConfigSchema.parse({
			http,
			oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
			attribute: { collectors: [{ collector: "TestScopeCollector" }] },
			rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
			resource: { parser: "SimpleParser" },
		});
	}

	const guardedConfig = configWithHttp({ callerAuth: { token: "caller-secret" } });

	it("serves decisions to a caller presenting the configured credential", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: guardedConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("x-caller-token", "caller-secret")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("rejects a caller with a valid subject token but no caller credential", async () => {
		// The subject JWT says who the token is about — never who supplied the
		// resource/action. Without the caller credential the request must not
		// reach the decision path at all.
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: guardedConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("caller_unauthenticated");
	});

	it("gates the batch endpoint on the same credential", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: guardedConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({ decisions: [{ resource: "project", action: "read" }] });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("caller_unauthenticated");
	});

	it("leaves the healthcheck reachable without a credential", async () => {
		// The container healthcheck (and every orchestrator probe) has no
		// credential to present; gating liveness would make the service unschedulable.
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: guardedConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const res = await request(app).get("/healthcheck");
		expect(res.status).toBe(200);
	});

	it("serves decisions with no caller credential configured — the gate is opt-in", async () => {
		// Deliberately optional in this pass: container deployments and the
		// cross-repo E2E must keep working without one.
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
	});

	it("warns at boot when a non-loopback bind has no caller authentication", async () => {
		const { calls, logger } = captureLogger();
		await createApp({
			pathResolver: (s: string) => s,
			config: configWithHttp({ hostname: "0.0.0.0" }),
			modules: [testModule, builtinKeyResolversModule],
			logger,
		});

		const warnings = calls.filter((c) => c.msg === "unauthenticated_non_loopback_bind");
		expect(warnings).toHaveLength(1);
		expect(warnings[0].level).toBe("warn");
		expect(warnings[0].obj).toMatchObject({ hostname: "0.0.0.0" });
	});

	it("stays quiet on a loopback bind — the sidecar case is the default", async () => {
		const { calls, logger } = captureLogger();
		await createApp({
			pathResolver: (s: string) => s,
			config: testConfig,
			modules: [testModule, builtinKeyResolversModule],
			logger,
		});

		expect(calls.filter((c) => c.msg === "unauthenticated_non_loopback_bind")).toHaveLength(0);
	});

	it("stays quiet on a non-loopback bind that does authenticate its callers", async () => {
		const { calls, logger } = captureLogger();
		await createApp({
			pathResolver: (s: string) => s,
			config: configWithHttp({ hostname: "0.0.0.0", callerAuth: { token: "caller-secret" } }),
			modules: [testModule, builtinKeyResolversModule],
			logger,
		});

		expect(calls.filter((c) => c.msg === "unauthenticated_non_loopback_bind")).toHaveLength(0);
	});

	it("refuses to boot a hand-built config whose http block is malformed", async () => {
		const handBuilt = { ...testConfig, http: null } as unknown as typeof testConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/^createApp: http must be a config object/);
	});

	it("refuses to boot a hand-built config whose caller credential is empty", async () => {
		const handBuilt = {
			...testConfig,
			http: { ...testConfig.http, callerAuth: { token: "" } },
		} as unknown as typeof testConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/^createApp: http\.callerAuth\.token must be a non-empty string/);
	});
});

describe("createApp — HS256 secret rotation (#112)", () => {
	/** 64 hex characters — 32 decoded bytes, the floor auth.provider#282 set. */
	const CURRENT_SECRET = "11".repeat(32);
	const RETIRED_SECRET = "22".repeat(32);

	/** Mints an access token the way the paired provider does, `kid` and all. */
	async function signWith(secret: string, kid?: string): Promise<string> {
		const header =
			kid === undefined ? { alg: "HS256", typ: "at+jwt" } : { alg: "HS256", typ: "at+jwt", kid };
		return await new SignJWT({ scope: "read:project" })
			.setProtectedHeader(header)
			.setIssuedAt()
			.setExpirationTime("1h")
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.sign(new TextEncoder().encode(secret));
	}

	/** A deployment mid-rotation: signing under `v1`, still honouring `v0`. */
	const rotatedConfig = AppConfigSchema.parse({
		oauth: {
			jwt: {
				secret: CURRENT_SECRET,
				kid: "v1",
				previousSecrets: [{ kid: "v0", secret: RETIRED_SECRET, expiresAt: "2999-01-01T00:00:00Z" }],
				mode: "verify",
				issuer: ISSUER,
				audience: AUDIENCE,
			},
		},
		attribute: { collectors: [{ collector: "TestScopeCollector" }] },
		rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
		resource: { parser: "SimpleParser" },
	});

	async function rotatedApp() {
		return await createApp({
			pathResolver: (s: string) => s,
			config: rotatedConfig,
			modules: [testModule, builtinKeyResolversModule],
		});
	}

	it.each([
		["the new secret, by kid", CURRENT_SECRET, "v1"],
		["the retired secret, by kid — the overlap window", RETIRED_SECRET, "v0"],
		["the new secret with no kid header", CURRENT_SECRET, undefined],
		["the retired secret with no kid header", RETIRED_SECRET, undefined],
	])("decides on a token signed with %s", async (_label, secret, kid) => {
		// This is the outage #112 is about: before rotation support, a token
		// signed with anything but the single configured secret was 401 from the
		// instant the provider cut over, until both services restarted together.
		const res = await request(await rotatedApp())
			.post("/verify")
			.set("Authorization", `Bearer ${await signWith(secret, kid)}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("still refuses a secret the deployment never held", async () => {
		const res = await request(await rotatedApp())
			.post("/verify")
			.set("Authorization", `Bearer ${await signWith("33".repeat(32), "v1")}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("refuses a kid the deployment was never configured with", async () => {
		const res = await request(await rotatedApp())
			.post("/verify")
			.set("Authorization", `Bearer ${await signWith(CURRENT_SECRET, "v9")}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(401);
	});

	it("logs a rotation mismatch at warn, not error — kid is attacker-controlled", async () => {
		// #107's distinction: an operator alerting on error must see a provider
		// outage, not a stream of invented kids from anyone who can reach the port.
		const logger: Logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: () => logger,
		};
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: rotatedConfig,
			modules: [testModule, builtinKeyResolversModule],
			logger,
		});

		await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${await signWith(CURRENT_SECRET, "v9")}`)
			.send({ resource: "project", action: "read" });

		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({
				err: expect.objectContaining({ code: "ERR_JWKS_NO_MATCHING_KEY" }),
			}),
			"jwt_token_rejected",
		);
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("keeps a single-secret deployment working untouched", async () => {
		// The umbrella E2E shape: one shared OAUTH_JWT_SECRET, no kid, no
		// previousSecrets — and the provider stamps a kid the verifier has never
		// been told about. That must keep deciding exactly as it did.
		const config = AppConfigSchema.parse({
			oauth: {
				jwt: { secret: CURRENT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE },
			},
			attribute: { collectors: [{ collector: "TestScopeCollector" }] },
			rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
			resource: { parser: "SimpleParser" },
		});
		const app = await createApp({
			pathResolver: (s: string) => s,
			config,
			modules: [testModule, builtinKeyResolversModule],
		});

		for (const kid of ["v0", undefined]) {
			const res = await request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${await signWith(CURRENT_SECRET, kid)}`)
				.send({ resource: "project", action: "read" });
			expect(res.status).toBe(200);
			expect(res.body.decision).toBe("allow");
		}
	});

	it("refuses to boot on a rotation block that never met the schema", async () => {
		// createApp accepts hand-built configs; the factory is what catches them.
		const handBuilt = {
			...rotatedConfig,
			oauth: {
				jwt: {
					...rotatedConfig.oauth.jwt,
					kid: undefined,
				},
			},
		} as unknown as typeof rotatedConfig;

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: handBuilt,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow(/^oauth\.jwt\.kid is required/);
	});

	it.each([
		["the current secret", { secret: "your-secret" }, /^oauth\.jwt\.secret must carry at least/],
		[
			"a retired secret",
			{
				previousSecrets: [{ kid: "v0", secret: "your-secret", expiresAt: "2999-01-01T00:00:00Z" }],
			},
			/^oauth\.jwt\.previousSecrets\[0\]\.secret must carry at least/,
		],
	])(
		"refuses to boot on a hand-built config whose %s is under the entropy floor (#114)",
		async (_label, override, message) => {
			const handBuilt = {
				...rotatedConfig,
				oauth: { jwt: { ...rotatedConfig.oauth.jwt, ...override } },
			} as unknown as typeof rotatedConfig;

			await expect(
				createApp({
					pathResolver: (s: string) => s,
					config: handBuilt,
					modules: [testModule, builtinKeyResolversModule],
				}),
			).rejects.toThrow(message);
		},
	);
});

/** A module whose collectors never answer — the stalled dependency #115 is about. */
const stallingModule: Module = {
	name: "stalling-module",
	async init(context) {
		context.attributeCollectorRegistry.register("StallingCollector", () => ({
			collect: () => new Promise<Attributes>(() => {}),
		}));
		context.ruleCollectorRegistry.register("StallingRuleCollector", () => ({
			collect: () => new Promise<Rule[]>(() => {}),
		}));
	},
};

describe("createApp — a stalled collector denies (#115)", () => {
	/** Bounds low enough that the stall is answered well inside the test's own timeout. */
	const bounds = { collectorTimeoutMs: 20, collectorDeadlineMs: 50 };

	const stalledApp = (config: Record<string, unknown>) =>
		createApp({
			pathResolver: (s: string) => s,
			config: AppConfigSchema.parse({
				oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
				resource: { parser: "SimpleParser" },
				verify: bounds,
				...config,
			}),
			modules: [testModule, stallingModule, builtinKeyResolversModule],
		});

	const ask = async (app: Awaited<ReturnType<typeof createApp>>) =>
		request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${await signToken({ scope: "read:project" })}`)
			.send({ resource: "project", action: "read" });

	it("answers a deny instead of holding the request open", async () => {
		const app = await stalledApp({
			attribute: { collectors: [{ collector: "StallingCollector" }] },
			rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
		});

		const res = await ask(app);

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("collector_timeout");
		// Not a 500: the caller asked whether the request is authorized, and the
		// answer the verifier can stand behind is "no". A 5xx invites the
		// enforcement layer to retry, or — worse — to treat the PDP as down and
		// apply its own fallback.
		expect(res.body.reason.groups).toEqual([]);
	});

	it("still denies where the same request with no rules at all would be allowed", async () => {
		// This is the whole of "fail closed", in one pair of cases. A rule
		// pipeline that answered with the rules it managed to collect would hand
		// this deployment an EMPTY rule set — and `onEmptyRuleSet: "allow"` turns
		// an empty rule set into a permit. A timeout must not be able to walk
		// through that door, so the timed-out pipeline never reaches the evaluator.
		const failOpenPolicy = { onEmptyRuleSet: "allow" as const };

		const allowing = await stalledApp({
			attribute: { collectors: [] },
			rule: { collectors: [{ collector: "EmptyRuleCollector" }], ...failOpenPolicy },
		});
		const control = await ask(allowing);
		// The control: this deployment really does allow a request that collects
		// no rules, so the case below is not passing for some other reason.
		expect(control.status).toBe(200);
		expect(control.body.decision).toBe("allow");

		const stalled = await stalledApp({
			attribute: { collectors: [] },
			rule: { collectors: [{ collector: "StallingRuleCollector" }], ...failOpenPolicy },
		});
		const res = await ask(stalled);

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("collector_timeout");
	});
});

describe("createApp — collector bounds, one reader at both boundaries (#115)", () => {
	// `createApp` constructs both pipelines, so it is the runtime guard for the
	// bounds they run under: a library consumer reaches it with a hand-built
	// config the schema never saw. It must refuse what `AppConfigSchema` refuses,
	// naming the same key in the same words.
	const buildApp = (verify: unknown) =>
		createApp({
			pathResolver: (s: string) => s,
			config: { ...testConfig, verify } as unknown as typeof testConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

	/** The message one boundary refused with, or `undefined` when it accepted the value. */
	const refusal = async (act: () => Promise<unknown>): Promise<string | undefined> => {
		try {
			await act();
			return undefined;
		} catch (cause) {
			return (cause as Error).message;
		}
	};

	const schemaRefusal = (verify: unknown, field: string): string | undefined => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
			attribute: { collectors: [] },
			rule: { collectors: [] },
			verify,
		});
		return result.success
			? undefined
			: result.error.issues.find((issue) => issue.path.at(-1) === field)?.message;
	};

	it.each([
		["collectorTimeoutMs", 0],
		["collectorTimeoutMs", -1],
		["collectorTimeoutMs", 1.5],
		["collectorTimeoutMs", null],
		["collectorTimeoutMs", ""],
		["collectorDeadlineMs", false],
		["collectorDeadlineMs", "abc"],
		["collectorDeadlineMs", 0],
		["collectorConcurrency", 0],
		["collectorConcurrency", 2.5],
	])("refuses verify.%s = %s at boot, in the schema's wording", async (field, value) => {
		const verify = { [field]: value };
		const fromApp = await refusal(() => buildApp(verify));

		expect(fromApp).toBeDefined();
		expect(schemaRefusal(verify, field)).toBe(fromApp);
	});

	it("takes the strings a hand-built env config carries", async () => {
		expect(
			await refusal(() =>
				buildApp({
					collectorTimeoutMs: "500",
					collectorDeadlineMs: "1500",
					collectorConcurrency: "4",
				}),
			),
		).toBeUndefined();
	});

	it("defaults when the bounds are absent", async () => {
		expect(await refusal(() => buildApp({}))).toBeUndefined();
	});
});
