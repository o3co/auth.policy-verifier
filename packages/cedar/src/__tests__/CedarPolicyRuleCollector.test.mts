// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes, CollectorContext, Logger } from "@o3co/auth.policy-verifier.core";
import { evaluate } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it, vi } from "vitest";
import {
	CedarPolicyRuleCollector,
	type NoDeterminingPolicy,
} from "../CedarPolicyRuleCollector.mjs";

/** A context the collector must never read — everything reaches the rule via attrs. */
const context: CollectorContext = {
	subject: { sub: "user-1" },
	resource: { raw: "document:42", resourceType: "document", resourceId: "42" },
	action: "read",
	signal: new AbortController().signal,
};

const REQUEST_FACTS: ReadonlyArray<[string, unknown]> = [
	["userId", "alice"],
	["requestAction", "read"],
	["requestResourceType", "Document"],
	["requestResourceId", "42"],
];

function attrsWith(entries: ReadonlyArray<[string, unknown]> = []): Attributes {
	return new Map<string, unknown>([...REQUEST_FACTS, ...entries]);
}

function fakeLogger(): { logger: Logger; error: ReturnType<typeof vi.fn> } {
	const error = vi.fn();
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error,
		fatal: vi.fn(),
		child: (): Logger => logger,
	} as Logger;
	return { logger, error };
}

async function collectRule(config: Record<string, unknown>, logger?: Logger) {
	const collector = new CedarPolicyRuleCollector(config, logger ? { logger } : undefined);
	const rules = await collector.collect(context);
	expect(rules).toHaveLength(1);
	return rules[0];
}

describe("CedarPolicyRuleCollector — config validation", () => {
	it("requires one of policyDir / policies", () => {
		expect(() => new CedarPolicyRuleCollector({})).toThrow(/one of policyDir or policies/);
	});

	it("refuses both policyDir and policies", () => {
		expect(
			() =>
				new CedarPolicyRuleCollector({
					policyDir: "x",
					policies: "permit(principal, action, resource);",
				}),
		).toThrow(/mutually exclusive/);
	});

	it("refuses a policy set that does not parse, at construction", () => {
		expect(() => new CedarPolicyRuleCollector({ policies: "permit(when;" })).toThrow(
			/failed to parse/,
		);
	});

	it("refuses an unknown onNoDeterminingPolicy", () => {
		expect(
			() =>
				new CedarPolicyRuleCollector({
					policies: "permit(principal, action, resource);",
					onNoDeterminingPolicy: "allow" as unknown as NoDeterminingPolicy,
				}),
		).toThrow(/onNoDeterminingPolicy must be one of abstain, deny/);
	});

	it("refuses a non-boolean logEvaluationErrors", () => {
		expect(
			() =>
				new CedarPolicyRuleCollector({
					policies: "permit(principal, action, resource);",
					logEvaluationErrors: "yes" as unknown as boolean,
				}),
		).toThrow(/logEvaluationErrors must be a boolean/);
	});

	it("refuses a malformed entity attribute mapping", () => {
		expect(
			() =>
				new CedarPolicyRuleCollector({
					policies: "permit(principal, action, resource);",
					principal: { attributes: { dept: 7 } },
				}),
		).toThrow(/principal\.attributes\.dept/);
	});
});

describe("CedarPolicyRuleCollector — rule metadata", () => {
	it("returns one rule in the configured group with the fixed code", async () => {
		const rule = await collectRule({
			policies: "permit(principal, action, resource);",
			ruleType: "authz-cedar",
		});
		expect(rule.ruleType).toBe("authz-cedar");
		expect(rule.code).toBe("cedar_deny");
		expect(rule.message).toBe("Denied by Cedar policy");
	});
});

describe("CedarPolicyRuleCollector — answer interpretation", () => {
	const DEPT_POLICY = `permit(principal, action == Action::"read", resource) when { principal.dept == "eng" };`;

	it("passes on a determining permit", async () => {
		const rule = await collectRule({
			policies: DEPT_POLICY,
			principal: { attributes: { dept: "department" } },
		});
		expect(rule.verify(attrsWith([["department", "eng"]]))).toBe(true);
	});

	it("fails on a determining forbid, even beside a permit", async () => {
		const rule = await collectRule({
			policies: `
				permit(principal, action, resource);
				forbid(principal, action, resource) when { context.suspended == true };
			`,
			context: { suspended: "suspended" },
		});
		expect(rule.verify(attrsWith([["suspended", true]]))).toBe(false);
		expect(rule.verify(attrsWith([["suspended", false]]))).toBe(true);
	});

	it("denies by default when no policy determines the request", async () => {
		// The permit's condition is simply false — no error, no determining
		// policy. The default is Cedar's own implicit deny: a pipeline whose
		// only rule group is Cedar must not pass a request no policy matched.
		const rule = await collectRule({
			policies: DEPT_POLICY,
			principal: { attributes: { dept: "department" } },
		});
		expect(rule.verify(attrsWith([["department", "sales"]]))).toBe(false);
	});

	it("denies by default on an empty policy set", async () => {
		// An empty policy set never determines anything — the shape a first
		// deployment reaches with policies it has not written yet.
		const rule = await collectRule({ policies: "" });
		expect(rule.verify(attrsWith())).toBe(false);
	});

	it("abstains when the deployment asks for it — the migration posture", async () => {
		// Still selectable, and still the right answer where Cedar is one group
		// beside TypeScript rules that own the rest of the surface.
		const rule = await collectRule({ policies: "", onNoDeterminingPolicy: "abstain" });
		expect(rule.verify(attrsWith())).toBe(true);
	});

	it("denies when the deployment spells the default out", async () => {
		const rule = await collectRule({ policies: "", onNoDeterminingPolicy: "deny" });
		expect(rule.verify(attrsWith())).toBe(false);
	});

	it("leaves a determining permit alone under either setting", async () => {
		// The knob decides only the no-determining-policy branch; a policy that
		// does determine the request is unaffected by it.
		for (const onNoDeterminingPolicy of ["abstain", "deny"] as const) {
			const rule = await collectRule({
				policies: DEPT_POLICY,
				principal: { attributes: { dept: "department" } },
				onNoDeterminingPolicy,
			});
			expect(rule.verify(attrsWith([["department", "eng"]]))).toBe(true);
		}
	});

	it("denies and logs on evaluation errors even under abstain — the fail-open trap", async () => {
		const { logger, error } = fakeLogger();
		// The policy reads principal.dept but no mapping supplies it: Cedar
		// answers deny with an empty reason and the cause only in errors[].
		const rule = await collectRule({ policies: DEPT_POLICY }, logger);
		expect(rule.verify(attrsWith())).toBe(false);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/does not have the attribute/);
	});

	it("denies when an erroring forbid would otherwise let the top-level allow stand", async () => {
		const { logger, error } = fakeLogger();
		const rule = await collectRule(
			{
				policies: `
					permit(principal, action, resource);
					forbid(principal, action, resource) when { principal.banned == true };
				`,
			},
			logger,
		);
		// `banned` is unmapped: the forbid errors and stops forbidding, Cedar's
		// top-level decision reads "allow" — the errors check must still deny.
		expect(rule.verify(attrsWith())).toBe(false);
		expect(error).toHaveBeenCalledOnce();
	});

	it("denies on a missing principal id", async () => {
		const { logger, error } = fakeLogger();
		const rule = await collectRule({ policies: "permit(principal, action, resource);" }, logger);
		const attrs = attrsWith();
		attrs.delete("userId");
		expect(rule.verify(attrs)).toBe(false);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/principal id/);
	});

	it("denies on malformed parents rather than silently un-membering", async () => {
		const { logger, error } = fakeLogger();
		const rule = await collectRule(
			{
				policies: "permit(principal, action, resource);",
				principal: { parents: { Group: "groups" } },
			},
			logger,
		);
		expect(rule.verify(attrsWith([["groups", [1, 2]]]))).toBe(false);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/groups/);
	});
});

describe("CedarPolicyRuleCollector — entity synthesis", () => {
	it("supports group membership via parents", async () => {
		// "deny" so that a non-matching permit is distinguishable from a match —
		// under the default abstain both read as a pass.
		const rule = await collectRule({
			policies: `permit(principal in Group::"admins", action, resource);`,
			onNoDeterminingPolicy: "deny",
			principal: { parents: { Group: "groups" } },
		});
		expect(rule.verify(attrsWith([["groups", ["admins"]]]))).toBe(true);
		expect(rule.verify(attrsWith([["groups", ["users"]]]))).toBe(false);
		// Absent memberships are a legitimate state, not an error.
		expect(rule.verify(attrsWith())).toBe(false);
	});

	it("supports entity-reference attributes (resource.owner == principal)", async () => {
		const rule = await collectRule({
			policies: `permit(principal, action == Action::"read", resource) when { resource.owner == principal };`,
			onNoDeterminingPolicy: "deny",
			resource: { attributes: { owner: { attribute: "resourceOwner", entityType: "User" } } },
		});
		expect(rule.verify(attrsWith([["resourceOwner", "alice"]]))).toBe(true);
		expect(rule.verify(attrsWith([["resourceOwner", "bob"]]))).toBe(false);
	});

	it("supports context mapping", async () => {
		const rule = await collectRule({
			policies: "permit(principal, action, resource) when { context.mfa == true };",
			context: { mfa: "mfaVerified" },
		});
		expect(rule.verify(attrsWith([["mfaVerified", true]]))).toBe(true);
	});
});

describe("CedarPolicyRuleCollector — layered PDP through core evaluate", () => {
	it("ANDs the cedar group with a TypeScript group", async () => {
		const cedarRule = await collectRule({
			policies: "permit(principal, action, resource);",
		});
		const tsRule = {
			ruleType: "scope",
			code: "invalid_scope",
			message: "Insufficient scope",
			verify: (attrs: Parameters<typeof cedarRule.verify>[0]) => attrs.get("scopeOk") === true,
		};

		const both = evaluate(attrsWith([["scopeOk", true]]), [cedarRule, tsRule]);
		expect(both.decision).toBe("allow");

		// Cedar permits, the TS group refuses: AND composes toward strictness.
		const tsDenies = evaluate(attrsWith([["scopeOk", false]]), [cedarRule, tsRule]);
		expect(tsDenies.decision).toBe("deny");
	});
});
