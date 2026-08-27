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

const envKeys = [
	"OAUTH_JWT_SECRET",
	"OAUTH_JWT_ISSUER",
	"OAUTH_JWT_AUDIENCE",
	"HTTP_HOSTNAME",
	"HTTP_PORT",
	"HTTP_PATH_PREFIX",
] as const;

/** application.conf leaves issuer/audience unset, so every load must supply them. */
function setRequiredEnv(): void {
	process.env.OAUTH_JWT_SECRET = "test-secret";
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

			expect(config.http).toEqual({ hostname: "0.0.0.0", port: 3000, pathPrefix: "" });
			expect(config.oauth.jwt.algorithm).toBe("HS256");
			expect(config.oauth.jwt.secret).toBe("test-secret");
			expect(config.oauth.jwt.validate).toBe(true);
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
		expect(config.rule.collectors.map((c) => c.collector)).toEqual([
			"ResourceActionScopeRuleCollector",
			"ResourceActionPermissionRuleCollector",
		]);
		expect(config.resource.parser).toBe("DotNotationResourceParser");
	});

	it("applies the optional environment substitutions from application.conf", () => {
		setRequiredEnv();
		process.env.HTTP_HOSTNAME = "127.0.0.1";
		process.env.HTTP_PORT = "8080";
		process.env.HTTP_PATH_PREFIX = "/auth";

		const config = loadAppConfig(configDirPath, "development");

		expect(config.http).toEqual({ hostname: "127.0.0.1", port: 8080, pathPrefix: "/auth" });
	});

	it("rejects an HS256 config with no secret in the environment", () => {
		expect(() => loadAppConfig(configDirPath, "development")).toThrow(
			/secret is required for HS256/,
		);
	});

	it("rejects an env name that escapes the config directory", () => {
		expect(() => loadAppConfig(configDirPath, "../secrets")).toThrow(/resolves outside/);
	});
});

describe("loadAppConfig — RFC 9068 requirements (#105)", () => {
	it("fails to load when the issuer is not supplied", () => {
		process.env.OAUTH_JWT_SECRET = "test-secret";
		process.env.OAUTH_JWT_AUDIENCE = "https://api.test";

		expect(() => loadAppConfig(configDirPath, "development")).toThrow();
	});

	it("fails to load when the audience is not supplied", () => {
		process.env.OAUTH_JWT_SECRET = "test-secret";
		process.env.OAUTH_JWT_ISSUER = "https://issuer.test";

		expect(() => loadAppConfig(configDirPath, "development")).toThrow();
	});
});
