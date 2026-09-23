// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

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
		expect(attributeCollectorRegistry.has("RequestContextAttributeCollector")).toBe(true);
		expect(attributeCollectorRegistry.has("PayloadClaimAttributeCollector")).toBe(true);
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
			subject: {},
			resource: { raw: "test", resourceType: "test" },
			action: "read",
			signal: new AbortController().signal,
		});

		expect(attrs.get("permissions")).toEqual(["admin", "read"]);
	});

	// #264: the factory is handed the config entry as the operator wrote it,
	// and the config schema passes a collector entry's fields through
	// unchecked. A string where a list was meant must stop the boot.
	it.each([
		["StaticPermissionCollector", { permissions: "posts.*" }, /permissions must be an array/],
		["StaticRoleCollector", { roles: "admin" }, /roles must be an array/],
	])(
		"refuses a %s config entry whose list field is a string (#264)",
		async (name, fields, message) => {
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

			const factory = attributeCollectorRegistry.get(name);
			expect(() => factory({ collector: name, ...fields })).toThrow(TypeError);
			expect(() => factory({ collector: name, ...fields })).toThrow(message);
		},
	);
});
