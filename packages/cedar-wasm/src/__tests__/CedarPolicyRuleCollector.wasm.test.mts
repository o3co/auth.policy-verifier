// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The collector through the real evaluator: what `packages/cedar` pins with a
 * scripted engine, pinned here end to end — mapping, entity synthesis, Cedar's
 * own semantics — so that moving the engine behind the port changed nothing a
 * deployment can observe. Importing the package registers the engine; nothing
 * here selects it by name except the one test that does so on purpose.
 */

import "../index.mjs";

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	CedarPolicyRuleCollector,
	cedarPolicyModule,
	type NoDeterminingPolicy,
} from "@o3co/auth.policy-verifier.cedar";
import {
	type AttributeCollectorFactory,
	type Attributes,
	type CollectorContext,
	evaluate,
	isAsyncRule,
	type Logger,
	Registry,
	type ResourceParserFactory,
	type Rule,
	type RuleCollectorFactory,
} from "@o3co/auth.policy-verifier.core";
import { describe, expect, it, vi } from "vitest";

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

async function collectRule(config: Record<string, unknown>, logger?: Logger): Promise<Rule> {
	const collector = await CedarPolicyRuleCollector.create(config, logger ? { logger } : undefined);
	const rules = await collector.collect(context);
	expect(rules).toHaveLength(1);
	const rule = rules[0];
	// The wasm engine answers synchronously, so the collector builds a plain Rule.
	expect(isAsyncRule(rule)).toBe(false);
	return rule as Rule;
}

describe("CedarPolicyRuleCollector on the wasm engine — selection", () => {
	it("is chosen without being named, and by name", async () => {
		await collectRule({ policies: "permit(principal, action, resource);" });
		await collectRule({ policies: "permit(principal, action, resource);", engine: "wasm" });
	});

	it("refuses a policy set that does not parse, at construction", async () => {
		await expect(CedarPolicyRuleCollector.create({ policies: "permit(when;" })).rejects.toThrow(
			/CedarPolicyRuleCollector: policies \(inline\) failed to parse/,
		);
	});

	it("names the offending file in a policyDir", async () => {
		const dir = mkdtempSync(join(tmpdir(), "cedar-policies-"));
		writeFileSync(join(dir, "ok.cedar"), "permit(principal, action, resource);\n");
		writeFileSync(join(dir, "broken.cedar"), "permit(when;\n");
		await expect(CedarPolicyRuleCollector.create({ policyDir: dir })).rejects.toThrow(
			/broken\.cedar/,
		);
	});

	it("is what the module's registry factory builds", async () => {
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
		const collector = await ruleCollectorRegistry.get("CedarPolicyRuleCollector")({
			policies: "permit(principal, action, resource);",
		});
		const [rule] = await collector.collect(context);
		expect(isAsyncRule(rule)).toBe(false);
		expect((rule as Rule).verify(attrsWith())).toBe(true);
	});
});

describe("CedarPolicyRuleCollector on the wasm engine — answer interpretation", () => {
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
		const rule = await collectRule({
			policies: DEPT_POLICY,
			principal: { attributes: { dept: "department" } },
		});
		expect(rule.verify(attrsWith([["department", "sales"]]))).toBe(false);
	});

	it("denies by default on an empty policy set", async () => {
		const rule = await collectRule({ policies: "" });
		expect(rule.verify(attrsWith())).toBe(false);
	});

	it("abstains when the deployment asks for it — the migration posture", async () => {
		const rule = await collectRule({ policies: "", onNoDeterminingPolicy: "abstain" });
		expect(rule.verify(attrsWith())).toBe(true);
	});

	it("leaves a determining permit alone under either setting", async () => {
		for (const onNoDeterminingPolicy of ["abstain", "deny"] as NoDeterminingPolicy[]) {
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
		const rule = await collectRule(
			{ policies: DEPT_POLICY, onNoDeterminingPolicy: "abstain" },
			logger,
		);
		expect(rule.verify(attrsWith())).toBe(false);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/does not have the attribute/);
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/"engine":"wasm"/);
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

describe("CedarPolicyRuleCollector on the wasm engine — entity synthesis", () => {
	it("supports group membership via parents", async () => {
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

describe("CedarPolicyRuleCollector on the wasm engine — layered PDP through core evaluate", () => {
	it("ANDs the cedar group with a TypeScript group", async () => {
		const cedarRule = await collectRule({
			policies: "permit(principal, action, resource);",
		});
		const tsRule: Rule = {
			ruleType: "scope",
			code: "invalid_scope",
			message: "Insufficient scope",
			verify: (attrs) => attrs.get("scopeOk") === true,
		};

		const both = await evaluate(attrsWith([["scopeOk", true]]), [cedarRule, tsRule]);
		expect(both.decision).toBe("allow");

		// Cedar permits, the TS group refuses: AND composes toward strictness.
		const tsDenies = await evaluate(attrsWith([["scopeOk", false]]), [cedarRule, tsRule]);
		expect(tsDenies.decision).toBe("deny");
	});
});
