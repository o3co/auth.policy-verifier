import { describe, expect, it } from "vitest";
import { evaluate } from "../evaluate.mjs";
import type { Attributes, Rule } from "../types.mjs";

const makeRule = (ruleType: string, code: string, result: boolean): Rule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	verify: (_attrs: Attributes) => result,
});

describe("evaluate", () => {
	it("returns allow when no rules are provided", () => {
		const attrs: Attributes = new Map();
		const result = evaluate(attrs, []);
		expect(result).toEqual({ decision: "allow" });
	});

	it("returns allow when single rule passes", () => {
		const attrs: Attributes = new Map();
		const rules = [makeRule("scope", "invalid_scope", true)];
		const result = evaluate(attrs, rules);
		expect(result).toEqual({ decision: "allow" });
	});

	it("returns deny when single rule fails", () => {
		const attrs: Attributes = new Map();
		const rules = [makeRule("scope", "invalid_scope", false)];
		const result = evaluate(attrs, rules);
		expect(result).toEqual({
			decision: "deny",
			code: "invalid_scope",
			message: "Failed: invalid_scope",
		});
	});

	it("returns allow when any rule in same group passes (OR within group)", () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", false),
			makeRule("scope", "invalid_scope", true),
		];
		const result = evaluate(attrs, rules);
		expect(result).toEqual({ decision: "allow" });
	});

	it("returns deny when all rules in a group fail", () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", false),
			makeRule("scope", "invalid_scope", false),
		];
		const result = evaluate(attrs, rules);
		expect(result).toEqual({
			decision: "deny",
			code: "invalid_scope",
			message: "Failed: invalid_scope",
		});
	});

	it("returns allow when all groups pass (AND across groups)", () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", true),
		];
		const result = evaluate(attrs, rules);
		expect(result).toEqual({ decision: "allow" });
	});

	it("returns deny when one group fails (AND across groups)", () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", false),
		];
		const result = evaluate(attrs, rules);
		expect(result).toEqual({
			decision: "deny",
			code: "no_permission",
			message: "Failed: no_permission",
		});
	});
});
