import { describe, expect, it } from "vitest";
import { AttributePipeline } from "../AttributePipeline.mjs";
import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
	VerifierPayload,
} from "../types.mjs";

const stubContext: CollectorContext = {
	payload: {} satisfies VerifierPayload,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
};

const makeCollector = (result: Attributes): AttributeCollector => ({
	collect: async (_ctx: CollectorContext) => result,
});

describe("AttributePipeline", () => {
	it("returns empty map when no collectors", async () => {
		const pipeline = new AttributePipeline([]);
		const result = await pipeline.collect(stubContext);
		expect(result.size).toBe(0);
	});

	it("returns attributes from a single collector", async () => {
		const attrs: Attributes = new Map([["scopes", ["read:user"]]]);
		const pipeline = new AttributePipeline([makeCollector(attrs)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("scopes")).toEqual(["read:user"]);
	});

	it("concatenates arrays from multiple collectors", async () => {
		const a: Attributes = new Map([["scopes", ["read:user"]]]);
		const b: Attributes = new Map([["scopes", ["write:user"]]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("scopes")).toEqual(["read:user", "write:user"]);
	});

	it("overwrites non-array values (last wins)", async () => {
		const a: Attributes = new Map([["userId", "1"]]);
		const b: Attributes = new Map([["userId", "2"]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("userId")).toBe("2");
	});

	it("merges different keys from multiple collectors", async () => {
		const a: Attributes = new Map([["userId", "1"]]);
		const b: Attributes = new Map([["scopes", ["read:user"]]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("userId")).toBe("1");
		expect(result.get("scopes")).toEqual(["read:user"]);
	});

	it("runs collectors in parallel", async () => {
		const order: number[] = [];
		const slow: AttributeCollector = {
			collect: async () => {
				await new Promise((r) => setTimeout(r, 50));
				order.push(1);
				return new Map([["a", "1"]]);
			},
		};
		const fast: AttributeCollector = {
			collect: async () => {
				order.push(2);
				return new Map([["b", "2"]]);
			},
		};
		const pipeline = new AttributePipeline([slow, fast]);
		await pipeline.collect(stubContext);
		expect(order).toEqual([2, 1]);
	});
});
