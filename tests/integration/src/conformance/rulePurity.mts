// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	Attributes,
	CollectorContext,
	ReadonlyAttributes,
	Rule,
} from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";

/** The collect half of a `RuleCollector`, which is all this suite needs. */
export type CollectRules = (context: CollectorContext) => Promise<Rule[]>;

/** One request, and the attributes the rules collected from it are judged against. */
export interface RulePurityCase {
	/** Case name, used in test titles. */
	name: string;
	/** The request the rules are collected from. */
	context: CollectorContext;
	/** Attributes to run the collected rules against. */
	attrs: Attributes;
}

/**
 * Hooks a rule collector must provide to be checked for rule purity. `cases`
 * carry the collector's own requests and attributes — the suite pins the
 * property, not any particular policy, so an allowing case and a denying case
 * are both worth supplying: a rule that answers `false` for everything passes
 * every purity check while deciding nothing.
 */
export interface RulePurityAdapter {
	/** Collector name, used in test titles. */
	name: string;
	collect: CollectRules;
	cases: RulePurityCase[];
}

/**
 * Wraps `context` so every object reachable through it can be revoked at once.
 *
 * A shallow `Proxy.revocable(context)` would only catch a rule that kept the
 * context object itself. The mistake is just as easily made one indirection in —
 * `const resource = ctx.resource` at collect time, `resource.resourceType`
 * inside `verify` — so each object read through the proxy is wrapped in its own
 * revocable proxy and registered here. Primitives are handed back as-is, which
 * is exactly the distinction the contract draws: copying a value out at collect
 * time is legal, holding a live reference into the request is not.
 *
 * Each target is wrapped **once**, memoized in a `WeakMap`, so the proxy has the
 * same object identity every time it is read. Wrapping per access would make
 * `ctx.resource === ctx.resource` false inside `collect`, and an honest
 * collector that compares or caches a sub-object would fail this suite for a
 * reason that exists only inside the harness — a gate that reports its own
 * artifacts as violations is one people learn to disbelieve. Memoizing does not
 * weaken the revoke: one proxy per target still means every proxy ever handed
 * out is registered, so revocation reaches a rule that kept `ctx.resource` just
 * as it reaches one that kept `ctx`.
 */
function revocableContext(context: CollectorContext): {
	proxy: CollectorContext;
	revoke: () => void;
} {
	const revokers: Array<() => void> = [];
	const wrapped = new WeakMap<object, object>();

	const wrap = <T extends object>(target: T): T => {
		const memoized = wrapped.get(target);
		if (memoized !== undefined) return memoized as T;

		const { proxy, revoke } = Proxy.revocable(target, {
			get(t, prop, receiver) {
				const value: unknown = Reflect.get(t, prop, receiver);
				return typeof value === "object" && value !== null ? wrap(value) : value;
			},
		});
		// Registered before any nested read can recurse back into this target.
		wrapped.set(target, proxy);
		revokers.push(revoke);
		return proxy;
	};

	const proxy = wrap(context);
	return {
		proxy,
		revoke: () => {
			for (const revoke of revokers) revoke();
		},
	};
}

/** Whether an error is the one a revoked proxy throws on any access. */
function isRevokedProxyError(error: unknown): boolean {
	return error instanceof TypeError && /revoked/.test(error.message);
}

/** Names a rule in an assertion message the way a reader would look for it. */
function describeRule(rule: Rule, index: number): string {
	return `rule[${String(index)}] (ruleType="${rule.ruleType}", code="${rule.code}")`;
}

/**
 * Runs the contract's deciding test: collect the rules, take the request away,
 * and ask them again.
 *
 * The rules are collected from a revocable view of `context`. Each rule is
 * verified once while the request is still reachable, the view is then revoked,
 * and each rule is verified again. A rule that copied what it needs out at
 * collect time answers identically; a rule that kept the context — or anything
 * live inside it — throws on the access, which is the violation, reported
 * against the rule that committed it.
 *
 * Determinism and non-mutation are checked in the same pass, because they are
 * the other two clauses of the same sentence in AGENTS.md and they are free
 * here: the first verify already gives an answer to compare against, and the
 * attributes are already in hand to snapshot.
 *
 * @returns each rule's answer, in collection order, so a caller can assert the
 *   collector decides something rather than passing vacuously.
 * @throws if any rule reads the request at verify time, mutates `attrs`, or
 *   answers inconsistently.
 */
export async function assertRuleIndependentOfContext(
	collect: CollectRules,
	context: CollectorContext,
	attrs: Attributes,
): Promise<boolean[]> {
	const { proxy, revoke } = revocableContext(context);
	const rules = await collect(proxy);

	const snapshot = JSON.stringify([...attrs]);
	const withContext = rules.map((rule) => rule.verify(attrs));

	if (JSON.stringify([...attrs]) !== snapshot) {
		throw new Error(
			"a rule mutated the attributes it was judged against. The evaluator hands the same map to " +
				"every rule in every group, so a write here changes the inputs of every group after it.",
		);
	}

	// Same map, same question, before anything else changes: an answer that
	// moves on its own is not a function of `attrs` at all.
	const repeated = rules.map((rule) => rule.verify(attrs));
	for (const [index, answer] of repeated.entries()) {
		if (answer !== withContext[index]) {
			throw new Error(
				`${describeRule(rules[index], index)} is not a deterministic function of its attributes: ` +
					`it answered ${String(withContext[index])} and then ${String(answer)} for the same map.`,
			);
		}
	}

	revoke();

	const withoutContext = rules.map((rule, index) => {
		try {
			return rule.verify(attrs);
		} catch (error) {
			if (isRevokedProxyError(error)) {
				throw new Error(
					`${describeRule(rules[index], index)} read its collector's context at verify time. ` +
						"A rule may fix what it looks for at collect time, but its answer must come from " +
						'`attrs` alone — see AGENTS.md "Collector / Rule / Attribute Contract".',
				);
			}
			throw error;
		}
	});

	for (const [index, answer] of withoutContext.entries()) {
		if (answer !== withContext[index]) {
			throw new Error(
				`${describeRule(rules[index], index)} changed its answer once the request was gone: ` +
					`${String(withContext[index])} with the context, ${String(answer)} without it.`,
			);
		}
	}

	return withoutContext;
}

/**
 * Conformance suite pinning rule purity
 * (o3co/auth.policy-verifier#152).
 *
 * `evaluate()` runs every rule group rather than stopping at the first failure,
 * and justifies it in a comment: "Rules are pure predicates over attributes by
 * contract, so running them all is safe." This suite is what turns that "by
 * contract" into something that fails a build. The same property is what makes
 * a rule testable in isolation and a decision cacheable, and what lets an engine
 * that only ever receives a decision document sit behind the same contract — a
 * rule that reads the live request is not portable to one.
 *
 * The check is behavioural rather than textual, so it cannot be satisfied by
 * renaming a variable: the request is genuinely taken away and the rule is
 * genuinely asked again.
 */
export function describeRulePurityConformance(adapter: RulePurityAdapter): void {
	describe(`rule purity conformance — ${adapter.name}`, () => {
		for (const testCase of adapter.cases) {
			describe(testCase.name, () => {
				it("answers the same once the request it was collected from is gone", async () => {
					const answers = await assertRuleIndependentOfContext(
						adapter.collect,
						testCase.context,
						testCase.attrs,
					);
					// Guards against a vacuous pass: a collector that returns nothing
					// satisfies every property below without deciding anything.
					expect(answers.length).toBeGreaterThan(0);
				});

				it("answers the same for a distinct map carrying equal attributes", async () => {
					// The map's identity must not be part of the answer, or "cacheable"
					// and "testable in isolation" both stop being true.
					const rules = await adapter.collect(testCase.context);
					const copy: Attributes = new Map(testCase.attrs);

					expect(rules.map((rule) => rule.verify(copy))).toEqual(
						rules.map((rule) => rule.verify(testCase.attrs)),
					);
				});

				it("only reads the attributes it is handed", async () => {
					// The read-only view `Rule.verify` declares, enforced at runtime for
					// the sake of a rule authored in JavaScript, where the type is gone.
					const rules = await adapter.collect(testCase.context);
					const readOnly: ReadonlyAttributes = new Map(testCase.attrs);
					const before = JSON.stringify([...readOnly]);

					for (const rule of rules) rule.verify(readOnly);

					expect(JSON.stringify([...readOnly])).toBe(before);
				});
			});
		}
	});
}
