// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { EventLogger } from "@o3co/auth.policy-verifier.core";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createCallerAuthMiddleware, resolveCallerAuth } from "#/http/callerAuth.mjs";

/** Records every structured event so a test can assert what an operator would see. */
function captureLogger(): { calls: Array<{ level: string; msg: string }>; logger: EventLogger } {
	const calls: Array<{ level: string; msg: string }> = [];
	return {
		calls,
		logger: {
			info: (_obj, msg) => calls.push({ level: "info", msg }),
			warn: (_obj, msg) => calls.push({ level: "warn", msg }),
			error: (_obj, msg) => calls.push({ level: "error", msg }),
		},
	};
}

/** Mounts the middleware in front of a trivial route so the gate can be exercised over HTTP. */
function appWith(header: string, token: string, logger: EventLogger = captureLogger().logger) {
	const app = express();
	app.use(createCallerAuthMiddleware({ header, token }, logger));
	app.post("/verify", (_req, res) => {
		res.status(200).json({ decision: "allow" });
	});
	return app;
}

describe("resolveCallerAuth", () => {
	const context = { caller: "createApp", path: "http.callerAuth" };

	it("returns undefined when the block is absent — caller auth is optional (#108)", () => {
		expect(resolveCallerAuth({ hostname: "127.0.0.1" }, context)).toBeUndefined();
	});

	it("returns undefined when the block exists but carries no token", () => {
		// The HOCON shape: the header default keeps the block alive even when the
		// token substitution resolved to nothing.
		expect(
			resolveCallerAuth({ callerAuth: { header: "x-caller-token" } }, context),
		).toBeUndefined();
	});

	it("defaults the header when only a token is supplied", () => {
		expect(resolveCallerAuth({ callerAuth: { token: "s3cret" } }, context)).toEqual({
			header: "x-caller-token",
			token: "s3cret",
		});
	});

	it.each([
		["a string", "s3cret"],
		["a number", 1],
		["an array", []],
		["null", null],
	])("rejects a callerAuth block that is %s", (_label, value) => {
		expect(() => resolveCallerAuth({ callerAuth: value }, context)).toThrow(
			/^createApp: http\.callerAuth must be a config object/,
		);
	});

	it("rejects a non-string token", () => {
		expect(() => resolveCallerAuth({ callerAuth: { token: 42 } }, context)).toThrow(
			/^createApp: http\.callerAuth\.token must be a non-empty string/,
		);
	});

	it("rejects an empty token instead of silently disabling the gate", () => {
		expect(() => resolveCallerAuth({ callerAuth: { token: "" } }, context)).toThrow(
			/^createApp: http\.callerAuth\.token must be a non-empty string/,
		);
	});

	it("rejects an empty header name", () => {
		expect(() =>
			resolveCallerAuth({ callerAuth: { header: "", token: "s3cret" } }, context),
		).toThrow(/^createApp: http\.callerAuth\.header must be a non-empty string/);
	});
});

describe("createCallerAuthMiddleware", () => {
	it("passes a request presenting the configured credential", async () => {
		const res = await request(appWith("x-caller-token", "s3cret"))
			.post("/verify")
			.set("x-caller-token", "s3cret")
			.send({});

		expect(res.status).toBe(200);
	});

	it("matches the header name case-insensitively, as HTTP requires", async () => {
		const res = await request(appWith("X-Caller-Token", "s3cret"))
			.post("/verify")
			.set("x-caller-token", "s3cret")
			.send({});

		expect(res.status).toBe(200);
	});

	it("rejects a request presenting no credential", async () => {
		const res = await request(appWith("x-caller-token", "s3cret")).post("/verify").send({});

		expect(res.status).toBe(401);
		expect(res.body).toEqual({
			decision: "deny",
			code: "caller_unauthenticated",
			message: "Caller authentication failed",
		});
	});

	it("answers a wrong credential exactly as it answers a missing one", async () => {
		// The endpoint is a decision oracle; the rejection must not tell a prober
		// whether the credential they guessed was the right shape.
		const missing = await request(appWith("x-caller-token", "s3cret")).post("/verify").send({});
		const wrong = await request(appWith("x-caller-token", "s3cret"))
			.post("/verify")
			.set("x-caller-token", "guess")
			.send({});

		expect(wrong.status).toBe(missing.status);
		expect(wrong.body).toEqual(missing.body);
	});

	it("rejects a credential that is a prefix of the configured one", async () => {
		const res = await request(appWith("x-caller-token", "s3cret"))
			.post("/verify")
			.set("x-caller-token", "s3c")
			.send({});

		expect(res.status).toBe(401);
	});

	it("rejects a credential that merely extends the configured one", async () => {
		const res = await request(appWith("x-caller-token", "s3cret"))
			.post("/verify")
			.set("x-caller-token", "s3cretx")
			.send({});

		expect(res.status).toBe(401);
	});

	it("logs the rejection so a probing campaign is visible to the operator", async () => {
		const { calls, logger } = captureLogger();
		await request(appWith("x-caller-token", "s3cret", logger))
			.post("/verify")
			.send({});

		expect(calls).toEqual([{ level: "warn", msg: "caller_auth_rejected" }]);
	});

	it("logs nothing for an accepted caller", async () => {
		const { calls, logger } = captureLogger();
		await request(appWith("x-caller-token", "s3cret", logger))
			.post("/verify")
			.set("x-caller-token", "s3cret")
			.send({});

		expect(calls).toEqual([]);
	});

	it("refuses to be constructed with an empty credential", () => {
		// Same posture as createTokenAuthenticator: a misbuilt config fails at
		// construction rather than serving requests that can never be rejected.
		expect(() => createCallerAuthMiddleware({ header: "x-caller-token", token: "" })).toThrow(
			/token must be a non-empty string/,
		);
	});
});
