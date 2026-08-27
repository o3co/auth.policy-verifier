// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type AttributePipeline,
	consoleLogger,
	type Decision,
	type DecisionReason,
	type EvaluateOptions,
	type EventLogger,
	evaluate,
	type ResourceParser,
	type RulePipeline,
	type VerifierPayload,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { decodeJwt, errors, type JWTPayload, jwtVerify } from "jose";

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
	/** Evaluator semantics overrides; omitted means engine defaults (deny on an empty rule set). */
	evaluateOptions?: EvaluateOptions;
	/** Most entries `POST /verify/batch` will decide in one request. Defaults to 50. */
	maxBatchSize?: number;
	/**
	 * Sink for the router's failure events (`jwt_token_rejected`,
	 * `jwt_verification_unavailable`, `verify_internal_error`). Defaults to the
	 * console-backed logger so failures are never silent, even in a deployment
	 * that wires nothing.
	 */
	logger?: EventLogger;
}

/** Default cap on `POST /verify/batch` entries when the config does not set one. */
export const DEFAULT_MAX_BATCH_SIZE = 50;

/**
 * One decision the caller is asking for. The subject is deliberately absent:
 * it comes from the verified token, never from the body — accepting one here
 * would let any token holder ask for a decision about somebody else.
 */
export interface DecisionRequest {
	resource: string;
	action: string;
	context?: Record<string, unknown>;
}

/**
 * What the endpoint decided, and for whom.
 *
 * The four inputs an engine needs — subject, resource, action, context — are
 * named explicitly, and the outcome carries a structured `reason` rather than a
 * bare allow/deny. That is what lets a heavy-class engine (OPA's
 * `input document → decision`, OpenFGA's `check(user, relation, object)`, Cedar)
 * sit behind this same contract: the request carries enough for each of them to
 * form its own query, and the response has somewhere to put what decided.
 */
export interface DecisionResponse {
	/** JWT `sub` of the token presented. Absent when the token carries none. */
	subject?: string;
	resource: string;
	action: string;
	decision: "allow" | "deny";
	/** Present on deny — the first failing group's representative rule. */
	code?: string;
	/** Present on deny — the first failing group's representative rule. */
	message?: string;
	reason: DecisionReason;
}

/** True for a non-empty string or a non-empty array of non-empty strings. */
function isPresent(value: string | string[] | undefined): boolean {
	return Array.isArray(value)
		? value.length > 0 && value.every((v) => typeof v === "string" && v !== "")
		: typeof value === "string" && value !== "";
}

/** Error envelope shared by every non-decision response. */
interface ErrorBody {
	decision: "deny";
	code: string;
	message: string;
}

const errorBody = (code: string, message: string): ErrorBody => ({
	decision: "deny",
	code,
	message,
});

/** Outcome of authenticating the caller: either the verified payload or the response to send. */
type Authentication =
	| { ok: true; payload: VerifierPayload }
	| { ok: false; status: number; body: ErrorBody };

/**
 * True when token verification could not be attempted or completed for reasons
 * unrelated to the presented token — the situation an operator must be able to
 * tell apart from a bad token (#107: a JWKS outage flips the whole fleet to
 * 401-deny while the verifier's own logs stay empty).
 *
 * Infrastructure side: a JWKS fetch timeout, a malformed JWKS document, a bare
 * `JOSEError` (`ERR_JOSE_GENERIC` — jose reserves the base class for the JWKS
 * fetch path: its only two throw sites are a non-200 JWKS response and a body
 * that fails to parse as JSON), or any non-jose error escaping `jwtVerify`
 * (fetch/DNS failures from the remote key getter, a broken key resolver).
 * Every subclass jose throws about the token itself is judged token-side —
 * deliberately including `JWKSNoMatchingKey`, because the `kid` that failed to
 * match is attacker-controllable and must not open an error-level log-flooding
 * channel; its `err.code` in the warn line still identifies a stale-JWKS
 * rotation problem.
 */
function isVerificationUnavailable(cause: unknown): boolean {
	if (!(cause instanceof errors.JOSEError)) {
		return true;
	}
	return (
		cause instanceof errors.JWKSTimeout ||
		cause instanceof errors.JWKSInvalid ||
		cause.code === "ERR_JOSE_GENERIC"
	);
}

/**
 * Validates one entry of a decision request. Returns the entry or the reason it
 * is unusable, phrased with `label` so a batch can name the offending index.
 */
function parseDecisionRequest(raw: unknown, label: string): DecisionRequest | string {
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
		return `${label} must be an object`;
	}
	const { resource, action, context } = raw as Record<string, unknown>;
	if (typeof resource !== "string" || resource === "") {
		return `${label}.resource must be a non-empty string`;
	}
	if (typeof action !== "string" || action === "") {
		return `${label}.action must be a non-empty string`;
	}
	// `typeof [] === "object"`, so arrays need excluding explicitly — an array
	// reaching `CollectorContext.requestContext` is a shape no collector expects.
	if (
		context !== undefined &&
		(typeof context !== "object" || context === null || Array.isArray(context))
	) {
		return `${label}.context must be an object`;
	}
	return { resource, action, context: context as Record<string, unknown> | undefined };
}

/**
 * Builds the Express router serving the decision endpoints.
 *
 * `POST /verify` — `Authorization: Bearer <jwt>`, body
 * `{ resource, action, context? }`; answers a {@link DecisionResponse} with 200
 * on allow and 403 on deny.
 *
 * `POST /verify/batch` — body `{ decisions: [{ resource, action, context? }, …] }`;
 * answers `200 { decisions: DecisionResponse[] }` in request order. The status
 * reports whether the batch was decided, not what it decided, so a batch of
 * denials is still 200 — the caller reads each entry. Filtering a list of N
 * resources is one round trip rather than N.
 *
 * Both answer 400 for a malformed body, 401 for authentication failures, and
 * 500 for anything unexpected.
 */
export function createVerifyRouter(config: VerifyRouterConfig): express.Router {
	const jwt = config.jwt;
	const maxBatchSize = config.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;
	const logger = config.logger ?? consoleLogger;

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

	/** Extracts and verifies the bearer token. Shared by both endpoints. */
	async function authenticate(req: express.Request): Promise<Authentication> {
		const rawAuthHeader = req.get("authorization");
		if (!rawAuthHeader) {
			return {
				ok: false,
				status: 401,
				body: errorBody("missing_token", "Authorization header is missing"),
			};
		}

		const authHeader = rawAuthHeader.trim();
		const spaceIndex = authHeader.indexOf(" ");
		const scheme = spaceIndex > 0 ? authHeader.slice(0, spaceIndex) : authHeader;
		const token = spaceIndex > 0 ? authHeader.slice(spaceIndex + 1).trim() : undefined;

		if (scheme.toLowerCase() !== "bearer") {
			return {
				ok: false,
				status: 401,
				body: errorBody("unsupported_scheme", `Unsupported authorization scheme: ${scheme}`),
			};
		}
		if (!token) {
			return {
				ok: false,
				status: 401,
				body: errorBody("missing_token", "Authorization header is missing"),
			};
		}

		let decoded: JWTPayload;
		try {
			if (jwt.validate) {
				// key is either a static key or a JWKS get-key function; both satisfy jwtVerify overloads
				const result = await jwtVerify(token, jwt.key as Parameters<typeof jwtVerify>[1], {
					algorithms: jwt.algorithms,
					issuer: jwt.issuer,
					audience: jwt.audience,
					typ: jwt.tokenType,
				});
				decoded = result.payload;
			} else {
				decoded = decodeJwt(token);
			}
		} catch (cause) {
			// Same 401 either way — the caller is unauthenticated regardless — but
			// the log line is what lets the operator tell a provider outage from a
			// bad token.
			if (isVerificationUnavailable(cause)) {
				logger.error({ err: cause }, "jwt_verification_unavailable");
			} else {
				logger.warn({ err: cause }, "jwt_token_rejected");
			}
			return {
				ok: false,
				status: 401,
				body: errorBody("invalid_token", "Invalid token"),
			};
		}

		return { ok: true, payload: { ...decoded, token, tokenType: scheme } };
	}

	/** Runs the pipelines and the evaluator for one entry. */
	async function decide(
		req: express.Request,
		payload: VerifierPayload,
		entry: DecisionRequest,
	): Promise<DecisionResponse> {
		const resource = config.resourceParser.parse(entry.resource);
		const requestId = req.get("x-request-id");
		const headers = requestId ? { "x-request-id": requestId } : undefined;
		const context = {
			payload,
			resource,
			action: entry.action,
			headers,
			requestContext: entry.context,
		};

		const [attrs, rules] = await Promise.all([
			config.attributePipeline.collect(context),
			config.rulePipeline.collect(context),
		]);

		return toResponse(payload, entry, evaluate(attrs, rules, config.evaluateOptions));
	}

	const router = express.Router();
	router.use(express.json());

	router.post("/verify", async (req: express.Request, res: express.Response) => {
		try {
			const auth = await authenticate(req);
			if (!auth.ok) {
				res.status(auth.status).json(auth.body);
				return;
			}

			const entry = parseDecisionRequest(req.body, "body");
			if (typeof entry === "string") {
				res.status(400).json(errorBody("invalid_request", entry));
				return;
			}

			const decision = await decide(req, auth.payload, entry);
			res.status(decision.decision === "deny" ? 403 : 200).json(decision);
		} catch (cause) {
			logger.error({ err: cause, endpoint: "/verify" }, "verify_internal_error");
			res.status(500).json(errorBody("internal_error", "Internal server error"));
		}
	});

	router.post("/verify/batch", async (req: express.Request, res: express.Response) => {
		try {
			const auth = await authenticate(req);
			if (!auth.ok) {
				res.status(auth.status).json(auth.body);
				return;
			}

			const raw = (req.body as { decisions?: unknown } | undefined)?.decisions;
			if (!Array.isArray(raw) || raw.length === 0) {
				res.status(400).json(errorBody("invalid_request", "decisions must be a non-empty array"));
				return;
			}
			if (raw.length > maxBatchSize) {
				res
					.status(400)
					.json(
						errorBody(
							"invalid_request",
							`decisions must contain at most ${maxBatchSize} entries, got ${raw.length}`,
						),
					);
				return;
			}

			// Validate the whole batch before deciding any of it: a caller that sent
			// one malformed entry gets told which, rather than a partial answer.
			const entries: DecisionRequest[] = [];
			for (const [index, item] of raw.entries()) {
				const entry = parseDecisionRequest(item, `decisions[${index}]`);
				if (typeof entry === "string") {
					res.status(400).json(errorBody("invalid_request", entry));
					return;
				}
				entries.push(entry);
			}

			const decisions = await Promise.all(entries.map((entry) => decide(req, auth.payload, entry)));
			res.status(200).json({ decisions });
		} catch (cause) {
			logger.error({ err: cause, endpoint: "/verify/batch" }, "verify_internal_error");
			res.status(500).json(errorBody("internal_error", "Internal server error"));
		}
	});

	return router;
}

/** Projects an engine `Decision` onto the wire contract, naming what it was about. */
function toResponse(
	payload: VerifierPayload,
	entry: DecisionRequest,
	decision: Decision,
): DecisionResponse {
	const base = {
		...(typeof payload.sub === "string" ? { subject: payload.sub } : {}),
		resource: entry.resource,
		action: entry.action,
		reason: decision.reason,
	};
	return decision.decision === "deny"
		? { ...base, decision: "deny", code: decision.code, message: decision.message }
		: { ...base, decision: "allow" };
}
