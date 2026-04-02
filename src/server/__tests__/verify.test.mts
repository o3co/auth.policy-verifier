import express from "express";
import jwt from "jsonwebtoken";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { PayloadScopeCollector } from "#/collectors/PayloadScopeCollector.mjs";
import { RequestContextCollector } from "#/collectors/RequestContextCollector.mjs";
import { AttributePipeline } from "#/engine/AttributePipeline.mjs";
import { RulePipeline } from "#/engine/RulePipeline.mjs";
import type { ResourceParser } from "#/engine/types.mjs";
import { DotNotationResourceParser } from "#/resource/DotNotationResourceParser.mjs";
import { ResourceActionScopeRuleCollector } from "#/rules/ResourceActionScopeRuleCollector.mjs";
import { createVerifyRouter } from "../routes/verify.mjs";

const JWT_SECRET = "test-secret";

function createTestApp(resourceParser?: ResourceParser) {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: { secret: JWT_SECRET, validate: true },
			resourceParser: resourceParser ?? new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
		}),
	);
	return app;
}

function createTestAppWithContext() {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: { secret: JWT_SECRET, validate: true },
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([
				new PayloadScopeCollector(),
				new RequestContextCollector(),
			]),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
		}),
	);
	return app;
}

describe("POST /verify", () => {
	const app = createTestApp();

	it("returns allow for valid token with matching scope", async () => {
		const token = jwt.sign({ scope: "read:project" }, JWT_SECRET);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("returns deny for valid token without matching scope", async () => {
		const token = jwt.sign({ scope: "write:project" }, JWT_SECRET);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("invalid_scope");
	});

	it("returns 401 when no Authorization header", async () => {
		const res = await request(app).post("/verify").send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("missing_token");
	});

	it("returns 401 for invalid JWT", async () => {
		const res = await request(app)
			.post("/verify")
			.set("Authorization", "Bearer invalid.token.here")
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("passes context to collectors", async () => {
		const app = createTestAppWithContext();
		const token = jwt.sign({ scope: "read:project" }, JWT_SECRET);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read", context: { ip: "203.0.113.1" } });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("works without context (backward compatible)", async () => {
		const app = createTestAppWithContext();
		const token = jwt.sign({ scope: "read:project" }, JWT_SECRET);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("returns 401 for expired JWT", async () => {
		const token = jwt.sign({ scope: "read:project" }, JWT_SECRET, { expiresIn: -1 });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});
});
