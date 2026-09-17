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
	computePolicyRevision,
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
	type RuleEvaluation,
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

/*
 * #244, through the real evaluator and the synchronous path: a denial is
 * `cedar_deny` whether a policy produced it or not, and the record has to be
 * able to tell. The three that are not a policy's — the request never built,
 * the engine refusing the call, Cedar's own diagnostic errors — are each pinned
 * here against Cedar itself rather than a scripted answer.
 */
describe("CedarPolicyRuleCollector on the wasm engine — the evaluation behind an answer (#244)", () => {
	const PERMIT_READ = `permit(principal, action == Action::"read", resource);`;
	const FORBID_ALL = "forbid(principal, action, resource);";
	const NEEDS_DEPT = `permit(principal, action, resource) when { principal.dept == "eng" };`;
	const revisionOf = (text: string) => computePolicyRevision([{ name: "policies", text }]);

	/** Asks a rule the way core does: the boolean back, the evaluation to a reporter. */
	const ask = (rule: Rule, attrs: Attributes) => {
		let evaluation: RuleEvaluation | undefined;
		const passed = rule.verify(attrs, (reported) => {
			evaluation = reported;
		});
		return { passed, evaluation };
	};

	it("names the loaded revision on a permit, a forbid and an implicit deny — all completed", async () => {
		const permit = await collectRule({ policies: PERMIT_READ });
		expect(ask(permit, attrsWith())).toEqual({
			passed: true,
			evaluation: { status: "completed", revision: revisionOf(PERMIT_READ) },
		});

		const forbid = await collectRule({ policies: FORBID_ALL });
		expect(ask(forbid, attrsWith())).toEqual({
			passed: false,
			evaluation: { status: "completed", revision: revisionOf(FORBID_ALL) },
		});

		// Nothing matched: Cedar's implicit deny is Cedar's answer.
		const unmatched = await collectRule({ policies: PERMIT_READ });
		expect(ask(unmatched, attrsWith([["requestAction", "delete"]]))).toEqual({
			passed: false,
			evaluation: { status: "completed", revision: revisionOf(PERMIT_READ) },
		});
	});

	it("never claims a revision when the request could not be built — Cedar did not run", async () => {
		const rule = await collectRule({ policies: PERMIT_READ }, fakeLogger().logger);
		const attrs = attrsWith();
		attrs.delete("userId");
		const answer = ask(rule, attrs);
		expect(answer).toEqual({ passed: false, evaluation: { status: "not_invoked" } });
		expect(JSON.stringify(answer)).not.toContain("sha256:");
	});

	it("reports a failed evaluation on Cedar's diagnostic errors — the policies ran, and did not decide", async () => {
		const { logger, error } = fakeLogger();
		const rule = await collectRule({ policies: NEEDS_DEPT }, logger);
		expect(ask(rule, attrsWith())).toEqual({
			passed: false,
			evaluation: { status: "failed", revision: revisionOf(NEEDS_DEPT) },
		});
		expect(error).toHaveBeenCalledOnce();
	});

	it("reports a failed evaluation, vouching for nothing, when the engine refuses the call", async () => {
		// Not an entity type path, so Cedar cannot even parse the request: the
		// engine throws, and no answer means nothing vouched for what ran.
		const { logger, error } = fakeLogger();
		const rule = await collectRule({ policies: PERMIT_READ }, logger);
		const answer = ask(rule, attrsWith([["requestResourceType", "not a type"]]));
		expect(answer).toEqual({
			passed: false,
			evaluation: {
				status: "failed",
				revision: null,
				loadedRevision: revisionOf(PERMIT_READ),
			},
		});
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/authorization call failed/);
	});

	it("changes the revision when a policy's contents change under the same policy id", async () => {
		// Both sets are one file of one policy, so Cedar calls the policy
		// `policy0` in each: the id cannot tell them apart, the revision must.
		const dirWith = (text: string) => {
			const dir = mkdtempSync(join(tmpdir(), "cedar-revision-"));
			writeFileSync(join(dir, "10-rule.cedar"), text);
			return dir;
		};
		const before = await collectRule({ policyDir: dirWith(PERMIT_READ) });
		const after = await collectRule({ policyDir: dirWith(FORBID_ALL) });
		const same = await collectRule({ policyDir: dirWith(PERMIT_READ) });

		const revision = (rule: Rule) => {
			const { evaluation } = ask(rule, attrsWith());
			if (evaluation?.status !== "completed") throw new Error("expected a completed evaluation");
			return evaluation.revision;
		};
		expect(revision(after)).not.toBe(revision(before));
		// …and an unchanged set, mounted somewhere else, keeps it.
		expect(revision(same)).toBe(revision(before));
	});

	it("boots under requireConfirmedRevision, which this engine can honour", async () => {
		const rule = await collectRule({ policies: PERMIT_READ, requireConfirmedRevision: true });
		expect(rule.verify(attrsWith())).toBe(true);
	});

	it("answers a plain boolean to an evaluator that passes no reporter — a deny stays a deny", async () => {
		// The mixed-install case, against real Cedar: an older `evaluate()` calls
		// `verify(attrs)` and reads the answer by truthiness.
		const forbid = await collectRule({ policies: FORBID_ALL });
		const answer = forbid.verify(attrsWith());
		expect(answer).toBe(false);
		expect(answer ? "allow" : "deny").toBe("deny");
	});

	it("carries it onto the decision's outcome through core evaluate", async () => {
		const rule = await collectRule({ policies: FORBID_ALL });
		const decision = await evaluate(attrsWith(), [rule]);
		expect(decision).toMatchObject({ decision: "deny", code: "cedar_deny" });
		expect(decision.reason.groups[0].evaluated[0].evaluation).toEqual({
			status: "completed",
			revision: revisionOf(FORBID_ALL),
		});
	});
});
