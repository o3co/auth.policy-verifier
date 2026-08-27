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
import { DEFAULT_MAX_BATCH_SIZE } from "../config/defaults.mjs";
import {
	createTokenAuthenticator,
	type VerifyRouterJwtConfig,
} from "../jwt/tokenAuthenticator.mjs";

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

/** Outcome of validating one decision request: either the parsed entry or the reason it is unusable. */
type ParsedDecisionRequest = { ok: true; request: DecisionRequest } | { ok: false; error: string };

/**
 * Validates one entry of a decision request. Returns the entry or the reason it
 * is unusable, phrased with `label` so a batch can name the offending index.
 */
function parseDecisionRequest(raw: unknown, label: string): ParsedDecisionRequest {
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
		return { ok: false, error: `${label} must be an object` };
	}
	const { resource, action, context } = raw as Record<string, unknown>;
	if (typeof resource !== "string" || resource === "") {
		return { ok: false, error: `${label}.resource must be a non-empty string` };
	}
	if (typeof action !== "string" || action === "") {
		return { ok: false, error: `${label}.action must be a non-empty string` };
	}
	// `typeof [] === "object"`, so arrays need excluding explicitly — an array
	// reaching `CollectorContext.requestContext` is a shape no collector expects.
	if (
		context !== undefined &&
		(typeof context !== "object" || context === null || Array.isArray(context))
	) {
		return { ok: false, error: `${label}.context must be an object` };
	}
	return {
		ok: true,
		request: { resource, action, context: context as Record<string, unknown> | undefined },
	};
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
	const maxBatchSize = config.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;
	const logger = config.logger ?? consoleLogger;
	// Constructing the authenticator runs assertVerifyRouterJwtConfig, so an
	// invalid hand-built jwt config still fails here, at router construction.
	const authenticator = createTokenAuthenticator(config.jwt, logger);

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
			const auth = await authenticator.authenticate(req.get("authorization"));
			if (!auth.ok) {
				res.status(401).json(errorBody(auth.code, auth.message));
				return;
			}

			const parsed = parseDecisionRequest(req.body, "body");
			if (!parsed.ok) {
				res.status(400).json(errorBody("invalid_request", parsed.error));
				return;
			}

			const decision = await decide(req, auth.payload, parsed.request);
			res.status(decision.decision === "deny" ? 403 : 200).json(decision);
		} catch (cause) {
			logger.error({ err: cause, endpoint: "/verify" }, "verify_internal_error");
			res.status(500).json(errorBody("internal_error", "Internal server error"));
		}
	});

	router.post("/verify/batch", async (req: express.Request, res: express.Response) => {
		try {
			const auth = await authenticator.authenticate(req.get("authorization"));
			if (!auth.ok) {
				res.status(401).json(errorBody(auth.code, auth.message));
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
				const parsed = parseDecisionRequest(item, `decisions[${index}]`);
				if (!parsed.ok) {
					res.status(400).json(errorBody("invalid_request", parsed.error));
					return;
				}
				entries.push(parsed.request);
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
