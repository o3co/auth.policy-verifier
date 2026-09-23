// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Rule } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrLiteralCompare } from "#/rules/AttrLiteralCompare.mjs";
import { AttrLiteralEqual } from "#/rules/AttrLiteralEqual.mjs";
import { AttrLiteralIn } from "#/rules/AttrLiteralIn.mjs";
import { AttrLiteralNotEqual } from "#/rules/AttrLiteralNotEqual.mjs";
import { AttrLiteralNotIn } from "#/rules/AttrLiteralNotIn.mjs";
import { AttrMatchRule } from "#/rules/AttrMatchRule.mjs";
import { AttrPairCompare } from "#/rules/AttrPairCompare.mjs";
import { AttrPairEqual } from "#/rules/AttrPairEqual.mjs";
import { AttrPairNotEqual } from "#/rules/AttrPairNotEqual.mjs";

/**
 * A comparison rule is built from a config object the caller keeps (#255).
 * Whatever the caller does to that object afterwards — replacing a field,
 * pushing to or splicing an array — must not reach the rule: it answers from
 * the values it validated at construction, and its `ruleType` and `message`
 * keep describing them.
 *
 * Each row names one mutation and the answers the rule gave at construction,
 * on attributes chosen so that a rule reading the mutated config would answer
 * differently. A mutation to a value the constructor refuses (`NaN`) is among
 * them: construction-time validation must hold for the rule's whole life.
 */
interface Row {
	name: string;
	build: () => { rule: Rule; mutate: () => void };
	answers: Array<[Record<string, unknown>, boolean]>;
}

// Each `build` keeps its own config object so `mutate` can reach it, as a
// host that constructed the rule itself could.
function row<C>(
	name: string,
	construct: (config: C) => Rule,
	config: C,
	mutate: (config: C) => void,
	answers: Array<[Record<string, unknown>, boolean]>,
): Row {
	return {
		name,
		build: () => {
			const rule = construct(config);
			return { rule, mutate: () => mutate(config) };
		},
		answers,
	};
}

const rows: Row[] = [
	row(
		"AttrLiteralEqual: replacing a",
		(c) => new AttrLiteralEqual(c),
		{ a: "role", v: "admin" },
		(c) => {
			c.a = "tier";
		},
		[
			[{ role: "admin" }, true],
			[{ tier: "admin" }, false],
		],
	),
	row(
		"AttrLiteralEqual: replacing v",
		(c) => new AttrLiteralEqual(c),
		{ a: "role", v: "admin" as string | number },
		(c) => {
			c.v = "guest";
		},
		[
			[{ role: "admin" }, true],
			[{ role: "guest" }, false],
		],
	),
	row(
		"AttrLiteralNotEqual: replacing a",
		(c) => new AttrLiteralNotEqual(c),
		{ a: "role", v: "banned" },
		(c) => {
			c.a = "tier";
		},
		[
			[{ role: "admin" }, true],
			[{ tier: "admin" }, false],
		],
	),
	row(
		"AttrLiteralNotEqual: replacing v with NaN, which the constructor refuses",
		(c) => new AttrLiteralNotEqual(c),
		{ a: "n", v: 1 },
		(c) => {
			c.v = Number.NaN;
		},
		[
			[{ n: 2 }, true],
			[{ n: 1 }, false],
		],
	),
	row(
		"AttrLiteralIn: replacing a",
		(c) => new AttrLiteralIn(c),
		{ a: "role", values: ["admin", "editor"] },
		(c) => {
			c.a = "tier";
		},
		[
			[{ role: "admin" }, true],
			[{ tier: "admin" }, false],
		],
	),
	row(
		"AttrLiteralIn: pushing to and splicing values",
		(c) => new AttrLiteralIn(c),
		{ a: "role", values: ["admin", "editor"] },
		(c) => {
			c.values.push("guest");
			c.values.splice(0, 1);
		},
		[
			[{ role: "admin" }, true],
			[{ role: "guest" }, false],
		],
	),
	row(
		"AttrLiteralNotIn: replacing a",
		(c) => new AttrLiteralNotIn(c),
		{ a: "role", values: ["banned"] },
		(c) => {
			c.a = "tier";
		},
		[
			[{ role: "admin" }, true],
			[{ tier: "admin" }, false],
		],
	),
	row(
		"AttrLiteralNotIn: pushing to and splicing values",
		(c) => new AttrLiteralNotIn(c),
		{ a: "role", values: ["banned", "suspended"] },
		(c) => {
			c.values.push("admin");
			c.values.splice(0, 1);
		},
		[
			[{ role: "admin" }, true],
			[{ role: "banned" }, false],
		],
	),
	row(
		"AttrLiteralCompare: replacing a",
		(c) => new AttrLiteralCompare(c),
		{ a: "age", op: "ge" as const, v: 18 },
		(c) => {
			c.a = "score";
		},
		[
			[{ age: 18 }, true],
			[{ score: 18 }, false],
		],
	),
	row(
		"AttrLiteralCompare: replacing op",
		(c) => new AttrLiteralCompare(c),
		{ a: "age", op: "ge" as "ge" | "lt", v: 18 },
		(c) => {
			c.op = "lt";
		},
		[
			[{ age: 18 }, true],
			[{ age: 17 }, false],
		],
	),
	row(
		"AttrLiteralCompare: replacing v with NaN, which the constructor refuses",
		(c) => new AttrLiteralCompare(c),
		{ a: "age", op: "ge" as const, v: 18 },
		(c) => {
			c.v = Number.NaN;
		},
		[
			[{ age: 18 }, true],
			[{ age: 17 }, false],
		],
	),
	row(
		"AttrPairEqual: replacing a",
		(c) => new AttrPairEqual(c),
		{ a: "x", b: "y" },
		(c) => {
			c.a = "z";
		},
		[
			[{ x: "k", y: "k" }, true],
			[{ z: "k", y: "k" }, false],
		],
	),
	row(
		"AttrPairEqual: replacing b",
		(c) => new AttrPairEqual(c),
		{ a: "x", b: "y" },
		(c) => {
			c.b = "z";
		},
		[
			[{ x: "k", y: "k" }, true],
			[{ x: "k", z: "k" }, false],
		],
	),
	row(
		"AttrPairNotEqual: replacing a",
		(c) => new AttrPairNotEqual(c),
		{ a: "x", b: "y" },
		(c) => {
			c.a = "z";
		},
		[
			[{ x: "k", y: "j" }, true],
			[{ z: "k", y: "j" }, false],
		],
	),
	row(
		"AttrPairNotEqual: replacing b",
		(c) => new AttrPairNotEqual(c),
		{ a: "x", b: "y" },
		(c) => {
			c.b = "z";
		},
		[
			[{ x: "k", y: "j" }, true],
			[{ x: "k", z: "j" }, false],
		],
	),
	row(
		"AttrPairCompare: replacing a",
		(c) => new AttrPairCompare(c),
		{ a: "x", op: "lt" as const, b: "y" },
		(c) => {
			c.a = "z";
		},
		[
			[{ x: 1, y: 2 }, true],
			[{ z: 1, y: 2 }, false],
		],
	),
	row(
		"AttrPairCompare: replacing b",
		(c) => new AttrPairCompare(c),
		{ a: "x", op: "lt" as const, b: "y" },
		(c) => {
			c.b = "z";
		},
		[
			[{ x: 1, y: 2 }, true],
			[{ x: 1, z: 2 }, false],
		],
	),
	row(
		"AttrPairCompare: replacing op",
		(c) => new AttrPairCompare(c),
		{ a: "x", op: "lt" as "lt" | "gt", b: "y" },
		(c) => {
			c.op = "gt";
		},
		[
			[{ x: 1, y: 2 }, true],
			[{ x: 2, y: 1 }, false],
		],
	),
	row(
		"AttrMatchRule: replacing a",
		(c) => new AttrMatchRule(c),
		{ a: "x", b: "y" },
		(c) => {
			c.a = "z";
		},
		[
			[{ x: "k", y: "k" }, true],
			[{ z: "k", y: "k" }, false],
		],
	),
];

describe("comparison rules copy their config at construction (#255)", () => {
	it.each(rows)("$name after construction changes nothing", ({ build, answers }) => {
		const { rule, mutate } = build();
		const ask = (attrs: Record<string, unknown>) => rule.verify(new Map(Object.entries(attrs)));
		// The row's answers are the construction-time ones.
		for (const [attrs, expected] of answers) {
			expect(ask(attrs), `before: ${JSON.stringify(attrs)}`).toBe(expected);
		}
		const ruleType = rule.ruleType;
		const message = rule.message;

		mutate();

		for (const [attrs, expected] of answers) {
			expect(ask(attrs), `after: ${JSON.stringify(attrs)}`).toBe(expected);
		}
		expect(rule.ruleType).toBe(ruleType);
		expect(rule.message).toBe(message);
	});
});
