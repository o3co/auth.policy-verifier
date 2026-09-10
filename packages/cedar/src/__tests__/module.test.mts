// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type AttributeCollectorFactory,
	Registry,
	type ResourceParserFactory,
	type RuleCollectorFactory,
} from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { CedarPolicyRuleCollector } from "../CedarPolicyRuleCollector.mjs";
import { registerCedarEngine } from "../engine.mjs";
import { cedarPolicyModule } from "../module.mjs";
import { RequestFactsCollector } from "../RequestFactsCollector.mjs";
import { scriptedEngine } from "./scriptedEngine.mjs";

// The factory builds a collector, and a collector needs an engine; the module
// itself registers none — that is the importing package's job. Registered
// under a name no other file uses and selected by config, so this file never
// competes with another one's registration should test files share a cache.
registerCedarEngine(scriptedEngine("scripted", false));

describe("cedarPolicyModule", () => {
	it("has name 'cedar-policy'", () => {
		expect(cedarPolicyModule.name).toBe("cedar-policy");
	});

	it("registers both collector factories", async () => {
		const attributeCollectorRegistry = new Registry<AttributeCollectorFactory>();
		const ruleCollectorRegistry = new Registry<RuleCollectorFactory>();
		const resourceParserRegistry = new Registry<ResourceParserFactory>();

		await cedarPolicyModule.init({
			pathResolver: (s: string) => s,
			config: {},
			attributeCollectorRegistry,
			ruleCollectorRegistry,
			resourceParserRegistry,
		});

		expect(attributeCollectorRegistry.get("RequestFactsCollector")({})).toBeInstanceOf(
			RequestFactsCollector,
		);
		expect(
			await ruleCollectorRegistry.get("CedarPolicyRuleCollector")({
				policies: "permit(principal, action, resource);",
				engine: "scripted",
			}),
		).toBeInstanceOf(CedarPolicyRuleCollector);
	});
});
