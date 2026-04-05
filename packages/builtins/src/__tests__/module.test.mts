import { describe, expect, it } from "vitest";
import { Registry, type AttributeCollector, type RuleCollector, type ResourceParser } from "@o3co/auth.policy-verifier.core";
import { builtinCollectorsModule } from "../module.mjs";

describe("builtinCollectorsModule", () => {
	it("has name 'builtin-collectors'", () => {
		expect(builtinCollectorsModule.name).toBe("builtin-collectors");
	});

	it("registers all builtin attribute collectors", async () => {
		const attributeCollectorRegistry = new Registry<AttributeCollector>();
		const ruleCollectorRegistry = new Registry<RuleCollector>();
		const resourceParserRegistry = new Registry<ResourceParser>();

		await builtinCollectorsModule.init({
			pathResolver: (s: string) => s,
			config: {},
			attributeCollectorRegistry,
			ruleCollectorRegistry,
			resourceParserRegistry,
		});

		expect(attributeCollectorRegistry.has("PayloadScopeCollector")).toBe(true);
		expect(attributeCollectorRegistry.has("PayloadSubjectIdCollector")).toBe(true);
		expect(attributeCollectorRegistry.has("RequestContextCollector")).toBe(true);
		expect(attributeCollectorRegistry.has("StaticPermissionCollector")).toBe(true);
		expect(attributeCollectorRegistry.has("StaticRoleCollector")).toBe(true);
	});

	it("registers all builtin rule collectors", async () => {
		const attributeCollectorRegistry = new Registry<AttributeCollector>();
		const ruleCollectorRegistry = new Registry<RuleCollector>();
		const resourceParserRegistry = new Registry<ResourceParser>();

		await builtinCollectorsModule.init({
			pathResolver: (s: string) => s,
			config: {},
			attributeCollectorRegistry,
			ruleCollectorRegistry,
			resourceParserRegistry,
		});

		expect(ruleCollectorRegistry.has("ResourceActionScopeRuleCollector")).toBe(true);
		expect(ruleCollectorRegistry.has("ResourceActionPermissionRuleCollector")).toBe(true);
	});

	it("registers DotNotationResourceParser", async () => {
		const attributeCollectorRegistry = new Registry<AttributeCollector>();
		const ruleCollectorRegistry = new Registry<RuleCollector>();
		const resourceParserRegistry = new Registry<ResourceParser>();

		await builtinCollectorsModule.init({
			pathResolver: (s: string) => s,
			config: {},
			attributeCollectorRegistry,
			ruleCollectorRegistry,
			resourceParserRegistry,
		});

		expect(resourceParserRegistry.has("DotNotationResourceParser")).toBe(true);
	});
});
