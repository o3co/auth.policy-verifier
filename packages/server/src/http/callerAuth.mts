// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Caller authentication for the decision endpoints (#108).
 *
 * The bearer token on `/verify` establishes the *subject* a decision is about.
 * It says nothing about which service supplied `resource` / `action` /
 * `context` — so an endpoint that checks only the subject token is still a
 * decision oracle: anyone who can route to the port can probe which tokens,
 * scopes and resources this deployment accepts, and make it do pipeline work
 * while they do.
 *
 * This module closes that with a shared credential between the enforcement
 * layer and the verifier, checked before anything else runs. It is a second,
 * orthogonal question — "may you ask?" — and so it travels in its own header
 * rather than overloading `Authorization`.
 *
 * The gate is OPTIONAL today; see `CALLER_AUTH_REQUIRED` in `config/defaults`
 * for the one-line change that makes it mandatory.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { consoleLogger, type EventLogger } from "@o3co/auth.policy-verifier.core";
import type express from "express";
import { DEFAULT_CALLER_AUTH_HEADER } from "../config/defaults.mjs";

/** Resolved caller-authentication parameters. Both fields are non-empty by construction. */
export interface CallerAuthConfig {
	/** Request header carrying the credential. Compared case-insensitively, as HTTP requires. */
	header: string;
	/** Shared credential the calling service must present verbatim. */
	token: string;
}

/**
 * Where a caller-auth config failure is reported from: the boundary the
 * operator called and the config path as they wrote it. Mirrors
 * {@link JwtConfigErrorContext} so both blocks of `createApp`'s config surface
 * fail the same way.
 */
export interface CallerAuthErrorContext {
	/** Boundary named in the message, e.g. `"createApp"`. */
	caller: string;
	/** Config path of the caller-auth block at that boundary, e.g. `"http.callerAuth"`. */
	path: string;
}

/** Throws unless `value` is a non-empty string, naming the field the operator wrote. */
function assertNonEmptyString(
	value: unknown,
	field: string,
	{ caller, path }: CallerAuthErrorContext,
): asserts value is string {
	if (typeof value !== "string" || value === "") {
		throw new Error(`${caller}: ${path}.${field} must be a non-empty string`);
	}
}

/**
 * Reads the optional caller-auth block off an `http` config.
 *
 * Returns `undefined` when the deployment did not configure one — either the
 * block is absent, or it exists with no token. The second case is the shape
 * HOCON produces: `token = ${?HTTP_CALLER_AUTH_TOKEN}` leaves the key absent
 * when the variable is unset, while the block itself survives because of the
 * header default. "Present but tokenless" therefore means off, not malformed.
 *
 * A block that *is* malformed throws rather than silently disabling the gate:
 * an empty credential is a configuration mistake, and reading it as "caller
 * auth is off" is exactly the silent failure this endpoint cannot afford.
 */
export function resolveCallerAuth(
	http: object,
	context: CallerAuthErrorContext,
): CallerAuthConfig | undefined {
	const raw: unknown = (http as { callerAuth?: unknown }).callerAuth;
	if (raw === undefined) {
		return undefined;
	}
	// An explicit `null` is not "absent": it is a value the operator wrote, and
	// the same boundary treatment `assertConfigObject` gives every other block.
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
		throw new Error(
			`${context.caller}: ${context.path} must be a config object, got ${raw === null ? "null" : Array.isArray(raw) ? "array" : typeof raw}`,
		);
	}

	const { header, token } = raw as { header?: unknown; token?: unknown };
	if (token === undefined) {
		return undefined;
	}
	assertNonEmptyString(token, "token", context);
	if (header === undefined) {
		return { header: DEFAULT_CALLER_AUTH_HEADER, token };
	}
	assertNonEmptyString(header, "header", context);
	return { header, token };
}

/**
 * Compares two credentials without leaking how far they matched.
 *
 * Both sides are hashed first so the comparison runs over fixed-width digests:
 * `timingSafeEqual` throws on a length mismatch, and comparing the raw strings
 * would leak the configured credential's length through that error path.
 */
function credentialMatches(presented: string, expected: string): boolean {
	const a = createHash("sha256").update(presented, "utf8").digest();
	const b = createHash("sha256").update(expected, "utf8").digest();
	return timingSafeEqual(a, b);
}

/**
 * Builds the middleware that authenticates the *calling service* before any
 * decision work happens.
 *
 * Mount it ahead of the verify router: a rejected caller is answered before the
 * request body is parsed, so an unauthenticated peer cannot spend the process's
 * time on JSON parsing or the collector pipelines either.
 *
 * A missing credential and a wrong one get the identical 401 — the endpoint is
 * an oracle, and the rejection must not tell a prober whether what they sent
 * had the right shape. Rejections are logged so a probing campaign is visible.
 *
 * Validates its own config at construction, the same posture
 * `createTokenAuthenticator` takes: a misbuilt config fails here rather than
 * serving requests it can never authenticate.
 */
export function createCallerAuthMiddleware(
	config: CallerAuthConfig,
	logger: EventLogger = consoleLogger,
): express.RequestHandler {
	const context: CallerAuthErrorContext = { caller: "createCallerAuthMiddleware", path: "config" };
	assertNonEmptyString(config.header, "header", context);
	assertNonEmptyString(config.token, "token", context);
	const { header, token } = config;

	return (req, res, next) => {
		// `req.get` is case-insensitive, so an operator may spell the configured
		// header however they like without changing what callers must send.
		const presented = req.get(header);
		if (presented !== undefined && credentialMatches(presented, token)) {
			next();
			return;
		}
		// The header name, never the presented value: the value is attacker-supplied
		// and may be a near-miss of the real credential.
		logger.warn({ header, path: req.path }, "caller_auth_rejected");
		res.status(401).json({
			decision: "deny",
			code: "caller_unauthenticated",
			message: "Caller authentication failed",
		});
	};
}
