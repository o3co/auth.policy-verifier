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

	it("returns undefined when the block is absent — caller auth is optional", () => {
		expect(resolveCallerAuth({ hostname: "127.0.0.1" }, context)).toBeUndefined();
	});

	it("returns undefined when the block exists but carries no token", () => {
		// The HOCON shape: the header default keeps the block alive even when the
		// token substitution resolved to nothing.
		expect(
			resolveCallerAuth({ callerAuth: { header: "x-caller-token" } }, context),
		).toBeUndefined();
	});

	// The schema checks the header whether or not a token is set, so the guard
	// does too: the same block gets the same verdict at both boundaries.
	it.each([
		["empty", ""],
		["not a field name", "x api key"],
	])("rejects a tokenless block whose header is %s, as the schema does", (_label, header) => {
		expect(() => resolveCallerAuth({ callerAuth: { header } }, context)).toThrow(
			/^createApp: http\.callerAuth\.header /,
		);
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

	// HTTP strips the spaces and tabs around a header value, and Node refuses
	// a request whose header value carries a control character, so no caller
	// can present such a token and every request would be refused. The
	// deployment fails at boot instead.
	it.each([
		["whitespace only", "   "],
		["a leading space", " s3cret"],
		["a trailing space", "s3cret "],
		["a leading tab", "\ts3cret"],
		["a trailing newline", "s3cret\n"],
		["a control character", "s3\u0001cret"],
		["a DEL", "s3cret\u007f"],
		// Node reads a header value's bytes as Latin-1, so no request carries a
		// character above U+00FF.
		["an ideographic space only", "\u3000"],
		["a byte-order mark", "\ufeffs3cret"],
		["a curly quote", "s3cret\u2019"],
		// Blank however it is spelled. A Latin-1 client could send this one, but
		// whitespace is a mistake, not a credential.
		["no-break spaces only", "\u00a0\u00a0"],
	])("rejects a token with %s, which no request can present", (_label, token) => {
		expect(() => resolveCallerAuth({ callerAuth: { token } }, context)).toThrow(
			/^createApp: http\.callerAuth\.token /,
		);
	});

	it.each([
		["an inner space", "s3 cret"],
		["an inner tab", "s3\tcret"],
		["a Latin-1 letter", "s3crét"],
	])("accepts a token with %s, which a request can present", (_label, token) => {
		expect(resolveCallerAuth({ callerAuth: { token } }, context)).toEqual({
			header: "x-caller-token",
			token,
		});
	});

	it.each([["X_Caller"], ["x.api~key"], ["x-caller-token"]])(
		"accepts the header name %j, which is RFC 9110 token characters",
		(header) => {
			expect(resolveCallerAuth({ callerAuth: { header, token: "s3cret" } }, context)).toEqual({
				header,
				token: "s3cret",
			});
		},
	);

	// A request header's name is an RFC 9110 token, so a configured name
	// with any other character never matches one.
	it.each([
		["whitespace only", "   "],
		["a leading space", " x-caller-token"],
		["an inner space", "x caller"],
		["a colon", "x-caller-token:"],
	])("rejects a header name with %s, which no request can carry", (_label, header) => {
		expect(() => resolveCallerAuth({ callerAuth: { header, token: "s3cret" } }, context)).toThrow(
			/^createApp: http\.callerAuth\.header /,
		);
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

	it("refuses to be constructed with a credential no request can present", () => {
		expect(() => createCallerAuthMiddleware({ header: "x-caller-token", token: "   " })).toThrow(
			/^createCallerAuthMiddleware: config\.token /,
		);
		expect(() => createCallerAuthMiddleware({ header: "x caller", token: "s3cret" })).toThrow(
			/^createCallerAuthMiddleware: config\.header /,
		);
	});

	it("refuses to be constructed with an empty credential", () => {
		// Same posture as createTokenAuthenticator: a misbuilt config fails at
		// construction rather than serving requests that can never be rejected.
		expect(() => createCallerAuthMiddleware({ header: "x-caller-token", token: "" })).toThrow(
			/token must be a non-empty string/,
		);
	});
});
