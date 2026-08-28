// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { evaluate } from "../evaluate.mjs";
import type { Attributes, ReadonlyAttributes, Rule } from "../types.mjs";

/*
 * The `Rule.verify` half of the Collector/Rule/Attribute contract
 * (o3co/auth.policy-verifier#152).
 *
 * AGENTS.md requires `verify` to be a deterministic, side-effect-free function
 * of `attrs`. Two of those words are checkable here, at the type level and at
 * the unit level; the third — "does not read the request at verify time" — is
 * behavioural and lives in `tests/integration/src/conformance/rulePurity.mts`,
 * which revokes the context and re-runs `verify`.
 */

/** Fails to compile unless `T` is exactly `true`. */
type Assert<T extends true> = T;

/** The type `Rule.verify` actually hands an implementation. */
type VerifyParam = Parameters<Rule["verify"]>[0];

/*
 * The parameter is a read-only view. "Side-effect-free" includes not writing
 * into the map the evaluator is about to hand to every other group, and a
 * `ReadonlyMap` is where that stops being a request in prose. If `Rule.verify`
 * ever widens back to a mutable `Map`, `"set" extends keyof VerifyParam`
 * becomes `true` and this line stops compiling — which is the assertion.
 */
type _VerifyCannotWrite = Assert<"set" extends keyof VerifyParam ? false : true>;
type _VerifyCannotDelete = Assert<"delete" extends keyof VerifyParam ? false : true>;
type _VerifyCannotClear = Assert<"clear" extends keyof VerifyParam ? false : true>;

/* Reading is untouched: a rule still gets `get` / `has` / iteration. */
type _VerifyCanRead = Assert<"get" extends keyof VerifyParam ? true : false>;

/*
 * The collector side is deliberately NOT narrowed. `AttributeCollector.collect`
 * builds its result by mutation and the pipeline merges those maps, so
 * `Attributes` stays a mutable `Map`; only the rule's view of it is read-only.
 */
type _CollectorStillWrites = Assert<"set" extends keyof Attributes ? true : false>;

/** A rule whose answer is a function of `attrs` and of nothing else. */
const requiresScope = (required: string): Rule => ({
	ruleType: "scope",
	code: "invalid_scope",
	message: `Token does not have required scope: ${required}`,
	verify(attrs: ReadonlyAttributes) {
		const scopes = attrs.get("scopes");
		return Array.isArray(scopes) && scopes.includes(required);
	},
});

describe("Rule.verify contract", () => {
	it("answers identically for two distinct maps carrying equal attributes", () => {
		// "Equal attrs give equal answers" is the whole of the contract's
		// determinism clause, and it is what makes a rule testable in isolation:
		// the map's identity must not be part of the answer.
		const rule = requiresScope("read:project");
		const first: Attributes = new Map([["scopes", ["read:project"]]]);
		const second: Attributes = new Map([["scopes", ["read:project"]]]);

		expect(rule.verify(first)).toBe(true);
		expect(rule.verify(second)).toBe(true);
		expect(rule.verify(new Map([["scopes", ["write:project"]]]))).toBe(false);
	});

	it("answers identically on repeated calls with the same map", () => {
		const rule = requiresScope("read:project");
		const attrs: Attributes = new Map([["scopes", ["read:project"]]]);

		expect(rule.verify(attrs)).toBe(true);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("leaves the attributes it was judged against untouched", () => {
		// The evaluator hands the same live map to every rule in every group
		// (`evaluate.mts` Phase 3). A rule that wrote into it would change the
		// inputs of every group after it, which is what the read-only view above
		// makes a compile error rather than a debugging session.
		const rule = requiresScope("read:project");
		const attrs: Attributes = new Map([["scopes", ["read:project"]]]);
		const before = [...attrs];

		evaluate(attrs, [rule, requiresScope("write:project")]);

		expect([...attrs]).toEqual(before);
	});
});
