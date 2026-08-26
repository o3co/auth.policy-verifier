// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type AttributePipeline,
	evaluate,
	type ResourceParser,
	type RulePipeline,
	type VerifierPayload,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { decodeJwt, type JWTPayload, jwtVerify } from "jose";

/**
 * JWT parameters used when signature validation is on. Every field a resource
 * server must check per RFC 9068 §4 is required here, so a deployment cannot
 * end up verifying the signature alone.
 */
export interface VerifyingJwtConfig {
	validate: true;
	// The `key` is produced by a KeyResolverFactory; its concrete type depends on
	// the algorithm (e.g. KeyObject for HS256, JWTVerifyGetKey for JWKS, etc.).
	// The route narrows it via cast when calling jwtVerify.
	key: unknown;
	algorithms: string[];
	/** Issuer(s) this deployment accepts. A token minted by anyone else is rejected. */
	issuer: string | string[];
	/** Audience identifying this resource server. A token minted for another service is rejected. */
	audience: string | string[];
	/**
	 * Accepted `typ` header — `"at+jwt"` for RFC 9068 access tokens. An `application/`
	 * prefix on either side is ignored when comparing. Pinning it is what keeps an
	 * `id_token`, refresh token or logout token signed with the same key from passing.
	 */
	tokenType: string;
}

/** Development-only shape: the token is decoded, never verified. */
export interface DecodingJwtConfig {
	validate: false;
}

/** JWT half of `VerifyRouterConfig`, discriminated on `validate`. */
export type VerifyRouterJwtConfig = VerifyingJwtConfig | DecodingJwtConfig;

/** Config for `createVerifyRouter`. The `jwt.key` type is library-specific and is narrowed at call-time. */
export interface VerifyRouterConfig {
	jwt: VerifyRouterJwtConfig;
	resourceParser: ResourceParser;
	attributePipeline: AttributePipeline;
	rulePipeline: RulePipeline;
}

/** True for a non-empty string or a non-empty array of non-empty strings. */
function isPresent(value: string | string[] | undefined): boolean {
	return Array.isArray(value)
		? value.length > 0 && value.every((v) => typeof v === "string" && v !== "")
		: typeof value === "string" && value !== "";
}

/**
 * Builds the Express router that serves `POST /verify`.
 *
 * Request: `Authorization: Bearer <jwt>`, body `{ resource: string, action: string, context?: object }`.
 * Response: `{ decision: "allow" }` (200), `{ decision: "deny", code, message }` (403),
 * or 400 for bad request / 401 for auth errors / 500 for unexpected.
 */
export function createVerifyRouter(config: VerifyRouterConfig): express.Router {
	const jwt = config.jwt;

	// Fail at construction rather than accept tokens with an unchecked iss/aud/typ.
	// A JavaScript caller can reach here with the fields missing even though the
	// TypeScript shape requires them.
	if (jwt.validate) {
		if (!isPresent(jwt.issuer)) {
			throw new Error(
				"createVerifyRouter: jwt.issuer is required when jwt.validate is true (RFC 9068 §4)",
			);
		}
		if (!isPresent(jwt.audience)) {
			throw new Error(
				"createVerifyRouter: jwt.audience is required when jwt.validate is true (RFC 9068 §4)",
			);
		}
		if (!isPresent(jwt.tokenType)) {
			throw new Error(
				"createVerifyRouter: jwt.tokenType is required when jwt.validate is true (RFC 9068 §4)",
			);
		}
	}

	const router = express.Router();
	router.use(express.json());

	router.post("/verify", async (req: express.Request, res: express.Response) => {
		try {
			const rawAuthHeader = req.get("authorization");
			if (!rawAuthHeader) {
				res.status(401).json({
					decision: "deny",
					code: "missing_token",
					message: "Authorization header is missing",
				});
				return;
			}

			const authHeader = rawAuthHeader.trim();
			const spaceIndex = authHeader.indexOf(" ");
			const scheme = spaceIndex > 0 ? authHeader.slice(0, spaceIndex) : authHeader;
			const token = spaceIndex > 0 ? authHeader.slice(spaceIndex + 1).trim() : undefined;

			if (scheme.toLowerCase() !== "bearer") {
				res.status(401).json({
					decision: "deny",
					code: "unsupported_scheme",
					message: `Unsupported authorization scheme: ${scheme}`,
				});
				return;
			}

			if (!token) {
				res.status(401).json({
					decision: "deny",
					code: "missing_token",
					message: "Authorization header is missing",
				});
				return;
			}

			let decoded: JWTPayload;
			if (jwt.validate) {
				try {
					// key is either a static key or a JWKS get-key function; both satisfy jwtVerify overloads
					const result = await jwtVerify(token, jwt.key as Parameters<typeof jwtVerify>[1], {
						algorithms: jwt.algorithms,
						issuer: jwt.issuer,
						audience: jwt.audience,
						typ: jwt.tokenType,
					});
					decoded = result.payload;
				} catch {
					res.status(401).json({
						decision: "deny",
						code: "invalid_token",
						message: "Invalid token",
					});
					return;
				}
			} else {
				try {
					decoded = decodeJwt(token);
				} catch {
					res.status(401).json({
						decision: "deny",
						code: "invalid_token",
						message: "Invalid token",
					});
					return;
				}
			}

			const payload: VerifierPayload = {
				...decoded,
				token,
				tokenType: scheme,
			};

			const { resource: rawResource, action, context: requestContext } = req.body;

			if (typeof rawResource !== "string" || rawResource === "") {
				res.status(400).json({
					decision: "deny",
					code: "invalid_request",
					message: "resource must be a non-empty string",
				});
				return;
			}
			if (typeof action !== "string" || action === "") {
				res.status(400).json({
					decision: "deny",
					code: "invalid_request",
					message: "action must be a non-empty string",
				});
				return;
			}

			const resource = config.resourceParser.parse(rawResource);
			const requestId = req.get("x-request-id");
			const headers = requestId ? { "x-request-id": requestId } : undefined;
			const context = { payload, resource, action, headers, requestContext };

			const [attrs, rules] = await Promise.all([
				config.attributePipeline.collect(context),
				config.rulePipeline.collect(context),
			]);

			const decision = evaluate(attrs, rules);

			if (decision.decision === "deny") {
				res.status(403).json(decision);
				return;
			}
			res.status(200).json(decision);
		} catch (_cause) {
			res.status(500).json({
				decision: "deny",
				code: "internal_error",
				message: "Internal server error",
			});
		}
	});

	return router;
}
