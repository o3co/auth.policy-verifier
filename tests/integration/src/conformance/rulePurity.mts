// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	Attributes,
	CollectorContext,
	CollectorRequest,
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
	/**
	 * The request the rules are collected from.
	 *
	 * A `CollectorRequest`, so a case states only facts about the request: the
	 * per-collector `signal` is the fan-out's to supply (#115), and here the
	 * harness *is* the fan-out. Supplying one anyway is how a case checks what
	 * its collector does when the request is cancelled — it is linked into the
	 * view the collector sees.
	 */
	context: CollectorRequest;
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
function revocableContext(request: CollectorRequest): {
	proxy: CollectorContext;
	revoke: () => void;
} {
	const revokers: Array<() => void> = [];
	const wrapped = new WeakMap<object, object>();

	const wrap = <T extends object>(target: T): T => {
		const memoized = wrapped.get(target);
		if (memoized !== undefined) return memoized as T;

		// An `AbortSignal` cannot be a `Proxy` — see `revocableSignal`.
		if (target instanceof AbortSignal) {
			const { view, revoke } = revocableSignal(target);
			wrapped.set(target, view);
			revokers.push(revoke);
			return view as unknown as T;
		}

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

	// The fan-out's job, done here because here the harness is the fan-out: a
	// collector is always handed a `signal`, so one has to exist before the
	// context is wrapped. A case that supplied its own is linked through
	// `revocableSignal`; one that did not gets a signal that never aborts.
	const context: CollectorContext = {
		...request,
		signal: request.signal ?? new AbortController().signal,
	};

	const proxy = wrap(context);
	return {
		proxy,
		revoke: () => {
			for (const revoke of revokers) revoke();
		},
	};
}

/**
 * The `AbortSignal` case, which is the one field of the context a collector is
 * *meant* to hold live — and the one that cannot be wrapped in a `Proxy`.
 *
 * Both halves of that matter, and they pull in opposite directions.
 *
 * **It cannot be a `Proxy`.** `AbortSignal`'s members are brand-checked against
 * the receiver's internal slots, and a proxy is not the signal. `signal.aborted`
 * happens to read through, but `addEventListener`, `AbortSignal.any([signal])`
 * and `fetch(url, { signal })` all throw `Method Map.prototype.get called on
 * incompatible receiver` — so wrapping it the way every other object is wrapped
 * would fail every collector that uses its signal for the thing it is for. That
 * is the harness reporting its own artifact as a violation, the mistake the
 * memoization above already exists to avoid.
 *
 * **It still has to be revocable.** A signal is a live view of request state:
 * `aborted` changes under a rule's feet, so a rule that kept one and read it
 * inside `verify` is exactly the violation this suite catches, and exempting the
 * field would have quietly opened a hole in the check the week it was added.
 *
 * So the view is a genuine `AbortSignal` — `AbortSignal.any` mints one linked to
 * the original, which keeps every brand check and the cancellation semantics
 * intact — and revoking shadows each of its members with an own accessor that
 * throws the same `TypeError` a revoked proxy throws. `isRevokedProxyError` then
 * recognises it, and the violation is reported against the rule that committed
 * it, in the same words as every other one.
 */
function revocableSignal(signal: AbortSignal): { view: AbortSignal; revoke: () => void } {
	const view = AbortSignal.any([signal]);
	return {
		view,
		revoke: () => {
			// The prototype chain's string-keyed members — `aborted`, `reason`,
			// `throwIfAborted`, `onabort` and the three `EventTarget` methods. An own
			// accessor shadows each; the instance's own symbol-keyed internals are
			// left alone, since nothing reads a signal through those.
			for (const key of signalMembers(view)) {
				Object.defineProperty(view, key, {
					configurable: true,
					get() {
						throw new TypeError("Cannot perform 'get' on a proxy that has been revoked");
					},
				});
			}
		},
	};
}

/** Every string-keyed member an `AbortSignal` answers, from its prototype chain. */
function signalMembers(signal: AbortSignal): string[] {
	const keys = new Set<string>();
	for (
		let proto: object | null = Object.getPrototypeOf(signal) as object | null;
		proto !== null && proto !== Object.prototype;
		proto = Object.getPrototypeOf(proto) as object | null
	) {
		for (const key of Object.getOwnPropertyNames(proto)) {
			if (key !== "constructor") keys.add(key);
		}
	}
	return [...keys];
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
	context: CollectorRequest,
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
		/**
		 * The case's request as a collector receives it, for the checks below that
		 * do not need the revocable view. Nothing here cancels — these ask what a
		 * rule answers, not what a collector does when the request goes away.
		 */
		const asContext = (testCase: RulePurityCase): CollectorContext => ({
			...testCase.context,
			signal: testCase.context.signal ?? new AbortController().signal,
		});

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
					const rules = await adapter.collect(asContext(testCase));
					const copy: Attributes = new Map(testCase.attrs);

					expect(rules.map((rule) => rule.verify(copy))).toEqual(
						rules.map((rule) => rule.verify(testCase.attrs)),
					);
				});

				it("only reads the attributes it is handed", async () => {
					// The read-only view `Rule.verify` declares, enforced at runtime for
					// the sake of a rule authored in JavaScript, where the type is gone.
					const rules = await adapter.collect(asContext(testCase));
					const readOnly: ReadonlyAttributes = new Map(testCase.attrs);
					const before = JSON.stringify([...readOnly]);

					for (const rule of rules) rule.verify(readOnly);

					expect(JSON.stringify([...readOnly])).toBe(before);
				});
			});
		}
	});
}
