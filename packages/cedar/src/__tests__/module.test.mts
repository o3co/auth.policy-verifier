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
import { cedarPolicyModule } from "../module.mjs";
import { RequestFactsCollector } from "../RequestFactsCollector.mjs";

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
			ruleCollectorRegistry.get("CedarPolicyRuleCollector")({
				policies: "permit(principal, action, resource);",
			}),
		).toBeInstanceOf(CedarPolicyRuleCollector);
	});
});
