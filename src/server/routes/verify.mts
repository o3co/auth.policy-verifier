import express from "express";
import jwt from "jsonwebtoken";
import type { AttributePipeline } from "#/engine/AttributePipeline.mjs";
import { evaluate } from "#/engine/evaluate.mjs";
import type { RulePipeline } from "#/engine/RulePipeline.mjs";
import type { ResourceParser, VerifierPayload } from "#/engine/types.mjs";

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
					jwt.verify(token, config.jwt.secret);
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
				...(jwt.decode(token) as jwt.JwtPayload),
				token,
				tokenType,
			};

			const { resource: rawResource, action } = req.body;
			const resource = config.resourceParser.parse(rawResource);
			const requestId = req.get("x-request-id");
			const headers = requestId ? { "x-request-id": requestId } : undefined;
			const context = { payload, resource, action, headers };

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
