// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Tests for the config loading path that main.mts boots from.
 *
 * These read the real files under templates/standalone/config/, so they cover
 * the shipped layering rather than a hand-built object: an env overlay that
 * contains only comments is an empty HOCON document, and it must fall back to
 * application.conf instead of failing to parse. Nothing else in the suite
 * exercises parseFile, so a HOCON parser regression is otherwise invisible
 * until the container fails to start.
 */
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { loadAppConfig } from "../loadConfig.js";

const configDirPath = fileURLToPath(new URL("../../config/", import.meta.url));

/**
 * 64 hex characters — 32 decoded bytes, the entropy floor the schema enforces
 * on every HS256 secret (#114). A short value now fails to load at all.
 */
const TEST_SECRET = "11".repeat(32);

const envKeys = [
	"OAUTH_JWT_SECRET",
	"OAUTH_JWT_ISSUER",
	"OAUTH_JWT_AUDIENCE",
	"OAUTH_JWT_MODE",
	"HTTP_HOSTNAME",
	"HTTP_PORT",
	"HTTP_PATH_PREFIX",
	"HTTP_CALLER_AUTH_TOKEN",
	"HTTP_CALLER_AUTH_HEADER",
	"OAUTH_JWT_JWKS_TIMEOUT_MS",
	"OAUTH_JWT_JWKS_COOLDOWN_MS",
	"OAUTH_JWT_JWKS_CACHE_MAX_AGE_MS",
	"OAUTH_JWT_MAX_TOKEN_AGE_SECONDS",
	"OAUTH_JWT_CLOCK_TOLERANCE_SECONDS",
	"VERIFY_MAX_BATCH_SIZE",
] as const;

/** application.conf leaves issuer/audience unset, so every load must supply them. */
function setRequiredEnv(): void {
	process.env.OAUTH_JWT_SECRET = TEST_SECRET;
	process.env.OAUTH_JWT_ISSUER = "https://issuer.test";
	process.env.OAUTH_JWT_AUDIENCE = "https://api.test";
}

afterEach(() => {
	for (const key of envKeys) {
		delete process.env[key];
	}
});

describe("loadAppConfig", () => {
	// Both shipped overlays are comment-only. They parse to an empty document,
	// which withFallback must resolve to the application.conf values.
	it.each(["development", "production"])(
		"resolves the %s overlay against application.conf",
		(env) => {
			setRequiredEnv();

			const config = loadAppConfig(configDirPath, env);

			// Loopback by default (#108): the shipped config is a sidecar config,
			// and reaching the port from another host is an explicit opt-in. The
			// callerAuth block exists but carries no token, which means the gate is off.
			expect(config.http).toEqual({
				hostname: "127.0.0.1",
				port: 3000,
				pathPrefix: "",
				callerAuth: { header: "x-caller-token" },
			});
			expect(config.oauth.jwt.algorithm).toBe("HS256");
			expect(config.oauth.jwt.secret).toBe(TEST_SECRET);
			expect(config.oauth.jwt.mode).toBe("verify");
			expect(config.oauth.jwt.issuer).toBe("https://issuer.test");
			expect(config.oauth.jwt.audience).toBe("https://api.test");
			expect(config.oauth.jwt.tokenType).toBe("at+jwt");
			expect(config.verify.maxBatchSize).toBe(50);
		},
	);

	it("registers the collectors declared in application.conf", () => {
		setRequiredEnv();

		const config = loadAppConfig(configDirPath, "development");

		expect(config.attribute.collectors.map((c) => c.collector)).toEqual([
			"PayloadScopeCollector",
			"PayloadSubjectIdCollector",
		]);
		// Scope-only, and the two lists are one decision (#113). Rule groups are
		// ANDed, so a rule reading an attribute no collector above produces is a
		// group nothing satisfies — which is a verifier that denies every request.
		// A permission rule may only join this list together with its supplier.
		expect(config.rule.collectors.map((c) => c.collector)).toEqual([
			"ResourceActionScopeRuleCollector",
		]);
		expect(config.resource.parser).toBe("DotNotationResourceParser");
	});

	it("applies the optional environment substitutions from application.conf", () => {
		setRequiredEnv();
		// 0.0.0.0 is the container opt-out of the loopback default — the value a
		// containerised deployment (and the cross-repo E2E) has to set explicitly.
		process.env.HTTP_HOSTNAME = "0.0.0.0";
		process.env.HTTP_PORT = "8080";
		process.env.HTTP_PATH_PREFIX = "/auth";

		const config = loadAppConfig(configDirPath, "development");

		expect(config.http).toMatchObject({
			hostname: "0.0.0.0",
			port: 8080,
			pathPrefix: "/auth",
		});
	});

	it("enables caller authentication from the environment (#108)", () => {
		setRequiredEnv();
		process.env.HTTP_CALLER_AUTH_TOKEN = "caller-secret";

		const config = loadAppConfig(configDirPath, "development");

		expect(config.http.callerAuth).toEqual({ header: "x-caller-token", token: "caller-secret" });
	});

	it("lets the caller-credential header be renamed for existing gateway conventions", () => {
		setRequiredEnv();
		process.env.HTTP_CALLER_AUTH_TOKEN = "caller-secret";
		process.env.HTTP_CALLER_AUTH_HEADER = "x-api-key";

		const config = loadAppConfig(configDirPath, "development");

		expect(config.http.callerAuth).toEqual({ header: "x-api-key", token: "caller-secret" });
	});

	it("refuses to boot when the caller credential is exported empty", () => {
		// The silent-failure case: `HTTP_CALLER_AUTH_TOKEN=` must not read as
		// "caller auth is off".
		setRequiredEnv();
		process.env.HTTP_CALLER_AUTH_TOKEN = "";

		expect(() => loadAppConfig(configDirPath, "development")).toThrow(/callerAuth[.,\s\S]*token/);
	});

	it("selects insecure-decode mode via OAUTH_JWT_MODE, requiring no key material (#134)", () => {
		// The value is the consent: only the literal string "insecure-decode"
		// selects the decode-only path, so a stray boolean-ish env value cannot.
		process.env.OAUTH_JWT_MODE = "insecure-decode";

		const config = loadAppConfig(configDirPath, "development");

		expect(config.oauth.jwt.mode).toBe("insecure-decode");
	});

	it("rejects a boolean-ish OAUTH_JWT_MODE left over from the removed OAUTH_JWT_VALIDATE", () => {
		setRequiredEnv();
		process.env.OAUTH_JWT_MODE = "false";

		expect(() => loadAppConfig(configDirPath, "development")).toThrow();
	});

	it("rejects an HS256 config with no secret in the environment", () => {
		expect(() => loadAppConfig(configDirPath, "development")).toThrow(
			/secret is required for HS256/,
		);
	});

	it.each([
		["a one-character OAUTH_JWT_SECRET", "s"],
		["the README's old example value", "your-secret"],
		["32 hex characters — 16 decoded bytes", "ab".repeat(16)],
	])("refuses to load %s (#114)", (_label, secret) => {
		// The floor applies to the shipped config as loaded, not only to
		// hand-built objects: `secret = ${?OAUTH_JWT_SECRET}` is where a weak
		// value actually enters a deployment.
		setRequiredEnv();
		process.env.OAUTH_JWT_SECRET = secret;

		expect(() => loadAppConfig(configDirPath, "development")).toThrow(
			/must carry at least 32 bytes/,
		);
	});

	it("rejects an env name that escapes the config directory", () => {
		expect(() => loadAppConfig(configDirPath, "../secrets")).toThrow(/resolves outside/);
	});
});

describe("loadAppConfig — RFC 9068 requirements (#105)", () => {
	it("fails to load when the issuer is not supplied", () => {
		process.env.OAUTH_JWT_SECRET = TEST_SECRET;
		process.env.OAUTH_JWT_AUDIENCE = "https://api.test";

		expect(() => loadAppConfig(configDirPath, "development")).toThrow();
	});

	it("fails to load when the audience is not supplied", () => {
		process.env.OAUTH_JWT_SECRET = TEST_SECRET;
		process.env.OAUTH_JWT_ISSUER = "https://issuer.test";

		expect(() => loadAppConfig(configDirPath, "development")).toThrow();
	});
});

describe("loadAppConfig — numeric knobs through the real 3-tier resolution (#157)", () => {
	// The knobs are read by `resolveBound` at both boundaries now, and this is the
	// path that proves the schema half still works where it actually runs: HOCON
	// substitutes `${?VAR}` as a STRING, and the ts.hocon zod adapter's coercion
	// walk only rewrites fields it recognises as numbers. A knob it cannot see
	// through must therefore coerce the string itself — which is exactly what
	// `resolveBound` does, and what a hand-built config already relied on.

	it("takes the numbers application.conf states when nothing overrides them", () => {
		setRequiredEnv();

		const config = loadAppConfig(configDirPath, "development");

		expect(config.http.port).toBe(3000);
		expect(config.oauth.jwt.jwksTimeoutMs).toBe(5000);
		expect(config.oauth.jwt.jwksCooldownMs).toBe(30_000);
		expect(config.oauth.jwt.jwksCacheMaxAgeMs).toBe(600_000);
		expect(config.oauth.jwt.maxTokenAgeSeconds).toBe(86_400);
		expect(config.oauth.jwt.clockToleranceSeconds).toBe(0);
		expect(config.verify.maxBatchSize).toBe(50);
		// The request limits (#118) travel the same path.
		expect(config.verify.maxBodyBytes).toBe(65_536);
		expect(config.verify.maxResourceLength).toBe(512);
		expect(config.verify.maxActionLength).toBe(64);
		expect(config.verify.maxContextEntries).toBe(64);
		expect(config.verify.maxContextValueLength).toBe(1024);
	});

	it("reads every numeric knob from the environment, where each arrives as a string", () => {
		setRequiredEnv();
		process.env.HTTP_PORT = "8080";
		process.env.OAUTH_JWT_JWKS_TIMEOUT_MS = "2500";
		process.env.OAUTH_JWT_JWKS_COOLDOWN_MS = "0";
		process.env.OAUTH_JWT_JWKS_CACHE_MAX_AGE_MS = "120000";
		process.env.OAUTH_JWT_MAX_TOKEN_AGE_SECONDS = "600";
		process.env.OAUTH_JWT_CLOCK_TOLERANCE_SECONDS = "60";
		process.env.VERIFY_MAX_BATCH_SIZE = "25";
		process.env.VERIFY_MAX_BODY_BYTES = "16384";
		process.env.VERIFY_MAX_RESOURCE_LENGTH = "128";
		process.env.VERIFY_MAX_ACTION_LENGTH = "32";
		process.env.VERIFY_MAX_CONTEXT_ENTRIES = "16";
		process.env.VERIFY_MAX_CONTEXT_VALUE_LENGTH = "256";

		const config = loadAppConfig(configDirPath, "development");

		expect(config.http.port).toBe(8080);
		expect(config.oauth.jwt.jwksTimeoutMs).toBe(2500);
		expect(config.oauth.jwt.jwksCooldownMs).toBe(0);
		expect(config.oauth.jwt.jwksCacheMaxAgeMs).toBe(120_000);
		expect(config.oauth.jwt.maxTokenAgeSeconds).toBe(600);
		expect(config.oauth.jwt.clockToleranceSeconds).toBe(60);
		expect(config.verify.maxBatchSize).toBe(25);
		expect(config.verify.maxBodyBytes).toBe(16_384);
		expect(config.verify.maxResourceLength).toBe(128);
		expect(config.verify.maxActionLength).toBe(32);
		expect(config.verify.maxContextEntries).toBe(16);
		expect(config.verify.maxContextValueLength).toBe(256);
	});

	it.each([
		["HTTP_PORT", "0"],
		["HTTP_PORT", "70000"],
		["OAUTH_JWT_JWKS_TIMEOUT_MS", "0"],
		["OAUTH_JWT_JWKS_COOLDOWN_MS", "-1"],
		["OAUTH_JWT_MAX_TOKEN_AGE_SECONDS", "1.5"],
		["OAUTH_JWT_CLOCK_TOLERANCE_SECONDS", "301"],
		["VERIFY_MAX_BATCH_SIZE", "0"],
		["VERIFY_MAX_BODY_BYTES", "0"],
		["VERIFY_MAX_RESOURCE_LENGTH", "-1"],
		["VERIFY_MAX_ACTION_LENGTH", "1.5"],
		["VERIFY_MAX_CONTEXT_ENTRIES", "abc"],
		["VERIFY_MAX_CONTEXT_VALUE_LENGTH", "0"],
	])("refuses to boot on %s=%s", (key, value) => {
		setRequiredEnv();
		process.env[key] = value;

		expect(() => loadAppConfig(configDirPath, "development")).toThrow();
	});

	it.each([
		"HTTP_PORT",
		"OAUTH_JWT_JWKS_COOLDOWN_MS",
		"OAUTH_JWT_CLOCK_TOLERANCE_SECONDS",
		"VERIFY_MAX_BATCH_SIZE",
		"VERIFY_MAX_BODY_BYTES",
		"VERIFY_MAX_CONTEXT_ENTRIES",
	])("refuses %s exported empty rather than reading it as zero", (key) => {
		// `VAR=` substitutes an empty string, and `Number("")` is 0 — which the
		// knobs whose floor is 0 would otherwise accept as a deliberate setting.
		// A zero cooldown is "refetch on every miss", the fetch storm the knob
		// exists to prevent; the same silent failure `http.callerAuth.token`
		// already refuses above.
		setRequiredEnv();
		process.env[key] = "";

		expect(() => loadAppConfig(configDirPath, "development")).toThrow();
	});
});
