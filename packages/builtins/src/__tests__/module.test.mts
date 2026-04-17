import {
	type AttributeCollectorFactory,
	Registry,
	type ResourceParserFactory,
	type RuleCollectorFactory,
} from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { builtinCollectorsModule } from "../module.mjs";

describe("builtinCollectorsModule", () => {
	it("has name 'builtin-collectors'", () => {
		expect(builtinCollectorsModule.name).toBe("builtin-collectors");
	});

	it("registers all builtin attribute collector factories", async () => {
		const attributeCollectorRegistry = new Registry<AttributeCollectorFactory>();
		const ruleCollectorRegistry = new Registry<RuleCollectorFactory>();
		const resourceParserRegistry = new Registry<ResourceParserFactory>();

		await builtinCollectorsModule.init({
			pathResolver: (s: string) => s,
			config: {},
			attributeCollectorRegistry,
			ruleCollectorRegistry,
			resourceParserRegistry,
		});

		expect(attributeCollectorRegistry.has("PayloadScopeCollector")).toBe(true);
		expect(attributeCollectorRegistry.has("PayloadSubjectIdCollector")).toBe(true);
		expect(attributeCollectorRegistry.has("StaticPermissionCollector")).toBe(true);
		expect(attributeCollectorRegistry.has("StaticRoleCollector")).toBe(true);
	});

	it("registers all builtin rule collector factories", async () => {
		const attributeCollectorRegistry = new Registry<AttributeCollectorFactory>();
		const ruleCollectorRegistry = new Registry<RuleCollectorFactory>();
		const resourceParserRegistry = new Registry<ResourceParserFactory>();

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

	it("registers DotNotationResourceParser factory", async () => {
		const attributeCollectorRegistry = new Registry<AttributeCollectorFactory>();
		const ruleCollectorRegistry = new Registry<RuleCollectorFactory>();
		const resourceParserRegistry = new Registry<ResourceParserFactory>();

		await builtinCollectorsModule.init({
			pathResolver: (s: string) => s,
			config: {},
			attributeCollectorRegistry,
			ruleCollectorRegistry,
			resourceParserRegistry,
		});

		expect(resourceParserRegistry.has("DotNotationResourceParser")).toBe(true);
	});

	it("creates a working StaticPermissionCollector from factory with config", async () => {
		const attributeCollectorRegistry = new Registry<AttributeCollectorFactory>();
		const ruleCollectorRegistry = new Registry<RuleCollectorFactory>();
		const resourceParserRegistry = new Registry<ResourceParserFactory>();

		await builtinCollectorsModule.init({
			pathResolver: (s: string) => s,
			config: {},
			attributeCollectorRegistry,
			ruleCollectorRegistry,
			resourceParserRegistry,
		});

		const factory = attributeCollectorRegistry.get("StaticPermissionCollector");
		const collector = factory({ permissions: ["admin", "read"] });
		const attrs = await collector.collect({
			payload: {},
			resource: { raw: "test", resourceType: "test" },
			action: "read",
		});

		expect(attrs.get("permissions")).toEqual(["admin", "read"]);
	});
});
