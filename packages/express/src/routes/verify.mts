import express from "express";
import { jwtVerify, decodeJwt } from "jose";
import {
	type AttributePipeline,
	evaluate,
	type ResourceParser,
	type RulePipeline,
	type VerifierPayload,
} from "@o3co/auth.policy-verifier.core";

export interface VerifyRouterConfig {
	jwt: { secret: string; validate: boolean };
	resourceParser: ResourceParser;
	attributePipeline: AttributePipeline;
	rulePipeline: RulePipeline;
}

export function createVerifyRouter(config: VerifyRouterConfig): express.Router {
	const router = express.Router();
	router.use(express.json());

	router.post("/verify", async (req: express.Request, res: express.Response) => {
		try {
			const [tokenType, token] = req.get("authorization")?.split(" ") ?? [];
			if (!token) {
				res.status(401).json({
					decision: "deny",
					code: "missing_token",
					message: "Authorization header is missing",
				});
				return;
			}

			if (config.jwt.validate) {
				try {
					await jwtVerify(token, new TextEncoder().encode(config.jwt.secret));
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
				...decodeJwt(token),
				token,
				tokenType,
			};

			const { resource: rawResource, action, context: requestContext } = req.body;
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
