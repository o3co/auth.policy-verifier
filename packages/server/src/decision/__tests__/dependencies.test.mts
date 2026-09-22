// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The decision's dependency boundary (#251), held rather than stated.
 *
 * `decision/README.md` says the decision reaches neither express nor the
 * metrics implementation nor any of the router's own layers. A check over the
 * *direct* imports of `decide.mts` would have passed while `countCollectorFailure`
 * was a value import out of `observability/metrics.mts` — which loads express
 * and prom-client at its top level — and that is what the review found. So
 * this walks value imports transitively, from the source, and proves on the
 * router that the walk fires.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

/** One `import … from "…"` statement, however many lines it spans. */
const IMPORT = /^import\s+(type\s+)?([\s\S]*?)\s+from\s+"([^"]+)";?$/gm;

/**
 * The specifiers a file imports for a value: not `import type …`, and not a
 * braces list whose every name is `type X`. Both are erased by the compiler,
 * so neither loads the module at runtime.
 */
function valueImports(file: string): string[] {
	const text = readFileSync(file, "utf8");
	const found: string[] = [];
	for (const [, typeOnly, clause, specifier] of text.matchAll(IMPORT)) {
		if (typeOnly) continue;
		if (clause.startsWith("{")) {
			const names = clause
				.slice(1, clause.lastIndexOf("}"))
				.split(",")
				.map((name) => name.trim())
				.filter((name) => name.length > 0);
			if (names.every((name) => name.startsWith("type "))) continue;
		}
		found.push(specifier);
	}
	return found;
}

/** Every source file reachable from `entry` through value imports, and every bare specifier met on the way. */
function reach(entry: string): { files: Set<string>; packages: Set<string> } {
	const files = new Set<string>();
	const packages = new Set<string>();
	const pending = [entry];
	while (pending.length > 0) {
		const file = pending.pop() as string;
		if (files.has(file)) continue;
		files.add(file);
		for (const specifier of valueImports(file)) {
			if (specifier.startsWith(".")) {
				pending.push(join(dirname(file), specifier.replace(/\.mjs$/, ".mts")));
			} else {
				packages.add(specifier);
			}
		}
	}
	return { files, packages };
}

const directoriesOf = (files: Set<string>): Set<string> =>
	new Set([...files].map((file) => dirname(file).slice(SRC.length + 1)));

describe("the decision's dependency boundary (#251)", () => {
	const decision = reach(join(SRC, "decision/decide.mts"));

	it("reaches core and nothing else outside the package — no express, no prom-client", () => {
		expect([...decision.packages]).toEqual(["@o3co/auth.policy-verifier.core"]);
	});

	it("reaches only its own directory and observability/ — none of http/, jwt/, config/, routes/", () => {
		expect(directoriesOf(decision.files)).toEqual(new Set(["decision", "observability"]));
		expect([...decision.files].some((file) => file.endsWith("observability/metrics.mts"))).toBe(
			false,
		);
	});

	it("fires: the same walk from the router reaches express and the router's other layers", () => {
		const router = reach(join(SRC, "routes/verify.mts"));
		expect(router.packages).toContain("express");
		expect(directoriesOf(router.files)).toEqual(
			new Set(["routes", "decision", "observability", "http", "jwt", "config"]),
		);
	});
});
