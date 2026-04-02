import { describe, expect, it } from "vitest";
import { RulePipeline } from "../RulePipeline.mjs";
import type { CollectorContext, Rule, RuleCollector, VerifierPayload } from "../types.mjs";

const stubContext: CollectorContext = {
	payload: {} satisfies VerifierPayload,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
};

const makeRuleCollector = (rules: Rule[]): RuleCollector => ({
	collect: async (_ctx: CollectorContext) => rules,
});

const stubRule = (ruleType: string, code: string): Rule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	verify: () => true,
});

describe("RulePipeline", () => {
	it("returns empty array when no collectors", async () => {
		const pipeline = new RulePipeline([]);
		const result = await pipeline.collect(stubContext);
		expect(result).toEqual([]);
	});

	it("returns rules from a single collector", async () => {
		const rules = [stubRule("scope", "invalid_scope")];
		const pipeline = new RulePipeline([makeRuleCollector(rules)]);
		const result = await pipeline.collect(stubContext);
		expect(result).toHaveLength(1);
		expect(result[0].code).toBe("invalid_scope");
	});

	it("flattens rules from multiple collectors", async () => {
		const a = [stubRule("scope", "invalid_scope")];
		const b = [stubRule("permission", "no_permission")];
		const pipeline = new RulePipeline([makeRuleCollector(a), makeRuleCollector(b)]);
		const result = await pipeline.collect(stubContext);
		expect(result).toHaveLength(2);
	});
});
