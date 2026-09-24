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
 *
 * The metrics port (#258) is held the same way, and more strictly: it is walked
 * through every import, type-only included. A type-only import loads nothing at
 * runtime, but it is still a direction — a port that names a type out of its
 * implementation's module, or a decision that does, depends on that module in
 * every sense but the loader's.
 *
 * The same walk holds two server-wide directions the source map
 * (`src/README.md`) states: the authentication contract in `auth/` reaches no
 * implementation, and neither `routes/` nor `config/` reaches `jwt/` (#259,
 * #260). Each is shown to fire on the side that is meant to depend.
 */
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

/** One `import … from "…"` statement, however many lines it spans. */
const IMPORT = /^import\s+(type\s+)?([\s\S]*?)\s+from\s+"([^"]+)";?$/gm;

/** One side-effect `import "…";`: it names nothing, but it loads the module. */
const SIDE_EFFECT = /^import\s+"([^"]+)";?$/gm;

/**
 * One `import("…")` with a literal specifier, import attributes or not: it
 * loads the module when it runs. A computed or template-literal specifier
 * cannot be followed and is not seen. An `import("…")` in a type position is
 * counted as a value import too — that errs towards a boundary failing, never
 * towards one passing unseen.
 */
const DYNAMIC = /\bimport\(\s*"([^"]+)"\s*[,)]/g;

/** One `export { … } from "…"` or `export * from "…"` re-export. */
const RE_EXPORT = /^export\s+(type\s+)?(\{[^}]*\}|\*(?:\s+as\s+\w+)?)\s+from\s+"([^"]+)";?$/gm;

type Imports = (file: string) => string[];

/**
 * The specifiers a file imports or re-exports for a value: not `import type …`,
 * and not a braces list whose every name is `type X`. Both are erased by the
 * compiler, so neither loads the module at runtime.
 */
const valueImports: Imports = (file) => {
	const text = readFileSync(file, "utf8");
	const found: string[] = [];
	for (const [, typeOnly, clause, specifier] of [
		...text.matchAll(IMPORT),
		...text.matchAll(RE_EXPORT),
	]) {
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
	for (const [, specifier] of text.matchAll(SIDE_EFFECT)) found.push(specifier);
	for (const [, specifier] of text.matchAll(DYNAMIC)) found.push(specifier);
	return found;
};

/** Every specifier a file imports or re-exports, type-only included. */
const allImports: Imports = (file) => {
	const text = readFileSync(file, "utf8");
	return [
		...[...text.matchAll(IMPORT), ...text.matchAll(RE_EXPORT)].map(
			([, , , specifier]) => specifier,
		),
		...[...text.matchAll(SIDE_EFFECT)].map(([, specifier]) => specifier),
		...[...text.matchAll(DYNAMIC)].map(([, specifier]) => specifier),
	];
};

/** The source file a relative specifier in `file` names. */
const sourceOf = (file: string, specifier: string): string =>
	join(dirname(file), specifier.replace(/\.mjs$/, ".mts"));

/** The source files a file's relative specifiers name. */
const sourceFiles = (file: string, imports: Imports): string[] =>
	imports(file)
		.filter((specifier) => specifier.startsWith("."))
		.map((specifier) => sourceOf(file, specifier));

/**
 * Every source file reachable from `entries` through `imports`, the entries
 * included, and every bare specifier met on the way.
 */
function reach(
	entries: string[],
	imports: Imports = valueImports,
): { files: Set<string>; packages: Set<string> } {
	const files = new Set<string>();
	const packages = new Set<string>();
	const pending = [...entries];
	while (pending.length > 0) {
		const file = pending.pop() as string;
		if (files.has(file)) continue;
		files.add(file);
		for (const specifier of imports(file)) {
			if (specifier.startsWith(".")) {
				pending.push(sourceOf(file, specifier));
			} else {
				packages.add(specifier);
			}
		}
	}
	return { files, packages };
}

const directoriesOf = (files: Set<string>): Set<string> =>
	new Set([...files].map((file) => dirname(file).slice(SRC.length + 1)));

const relative = (file: string): string => file.slice(SRC.length + 1);

const CORE = "@o3co/auth.policy-verifier.core";
const METRICS = join(SRC, "observability/metrics.mts");
const PORT = join(SRC, "observability/decisionMetrics.mts");

describe("the decision's dependency boundary (#251)", () => {
	const decision = reach([join(SRC, "decision/decide.mts")]);

	it("reaches core and nothing else outside the package — no express, no prom-client", () => {
		expect([...decision.packages]).toEqual([CORE]);
	});

	it("reaches only its own directory and observability/ — none of http/, jwt/, config/, routes/", () => {
		expect(directoriesOf(decision.files)).toEqual(new Set(["decision", "observability"]));
		expect(decision.files.has(METRICS)).toBe(false);
	});

	it("fires: the same walk from the router reaches express and the router's other layers", () => {
		const router = reach([join(SRC, "routes/verify.mts")]);
		expect(router.packages).toContain("express");
		expect(directoriesOf(router.files)).toEqual(
			new Set(["routes", "decision", "observability", "http", "config"]),
		);
	});
});

describe("the metrics port, apart from its prom-client implementation (#258)", () => {
	it("the port reaches core and nothing else outside the package, not even for a type", () => {
		const port = reach([PORT], allImports);
		expect([...port.packages]).toEqual([CORE]);
		expect(port.files.has(METRICS)).toBe(false);
	});

	it("the decision reaches observability/metrics.mts through no import at all, type-only included", () => {
		const decision = reach([join(SRC, "decision/decide.mts")], allImports);
		expect([...decision.files].map(relative)).not.toContain(relative(METRICS));
		expect([...decision.packages]).toEqual([CORE]);
	});

	it("no file in observability/ reaches itself through any import — failure.mts and metrics.mts included", () => {
		const directory = join(SRC, "observability");
		const cyclic = readdirSync(directory)
			.filter((name) => name.endsWith(".mts"))
			.map((name) => join(directory, name))
			.filter((file) => reach(sourceFiles(file, allImports), allImports).files.has(file))
			.map(relative);
		expect(cyclic).toEqual([]);
	});

	it("fires: the same walk from the implementation reaches express and prom-client", () => {
		const metrics = reach([METRICS], allImports);
		expect(metrics.packages).toContain("express");
		expect(metrics.packages).toContain("prom-client");
	});
});

/** The `.mts` source files directly inside one directory of `src/`, or none if it does not exist. */
function sourcesIn(directory: string): string[] {
	const path = join(SRC, directory);
	if (!existsSync(path)) return [];
	return readdirSync(path)
		.filter((name) => name.endsWith(".mts"))
		.map((name) => join(path, name));
}

/** The files of `files` that live in one directory of `src/`, relative to `src/`. */
const within = (files: Set<string>, directory: string): string[] =>
	[...files].map(relative).filter((file) => file.startsWith(`${directory}/`));

/** The directories of `src/` with a file that exports an interface or type named `name`. */
function declaringDirectories(name: string): string[] {
	const declaration = new RegExp(`^export (?:interface|type) ${name}\\b`, "m");
	return ["auth", "jwt", "config", "routes"].filter((directory) =>
		sourcesIn(directory).some((file) => declaration.test(readFileSync(file, "utf8"))),
	);
}

describe("the authentication contract, apart from the JWT implementation (#259)", () => {
	it.each([
		"TokenAuthenticator",
		"AuthenticationResult",
		"TokenAuthenticatorFactory",
		"TokenAuthenticatorDependencies",
		"ServerModuleContext",
		"KeyResolver",
		"KeyResolverFactory",
	])("%s is declared in auth/, and nowhere else", (name) => {
		expect(declaringDirectories(name)).toEqual(["auth"]);
	});

	it("auth/ reaches core and nothing else, not even for a type — no jose, no jwt/", () => {
		const contract = reach(sourcesIn("auth"), allImports);
		expect(contract.files.size).toBeGreaterThan(0);
		expect([...contract.packages]).toEqual([CORE]);
		expect(directoriesOf(contract.files)).toEqual(new Set(["auth"]));
	});

	it("routes/ reaches jwt/ through no import at all, type-only included", () => {
		const router = reach(sourcesIn("routes"), allImports);
		expect(within(router.files, "jwt")).toEqual([]);
		expect(router.packages).not.toContain("jose");
	});

	it("fires: jwt/ implements the contract — the same walk from it reaches auth/ and jose", () => {
		const jwt = reach(sourcesIn("jwt"), allImports);
		expect(within(jwt.files, "auth")).not.toEqual([]);
		expect(jwt.packages).toContain("jose");
	});

	it("fires: createApp is what reaches jwt/ — it builds the default authenticator", () => {
		const app = reach([join(SRC, "app.mts")]);
		expect(within(app.files, "jwt")).not.toEqual([]);
		expect(app.packages).toContain("jose");
	});
});

describe("config/ and jwt/ have one direction: jwt/ → config/ (#260)", () => {
	it("no file in config/ reaches jwt/ through any import, type-only included", () => {
		const config = reach(sourcesIn("config"), allImports);
		expect(within(config.files, "jwt")).toEqual([]);
		expect(config.packages).not.toContain("jose");
	});

	it("fires: the same walk from jwt/ reaches config/", () => {
		const jwt = reach(sourcesIn("jwt"), allImports);
		expect(within(jwt.files, "config")).not.toEqual([]);
	});
});

describe("the import walk itself", () => {
	it("sees a side-effect import, which loads a module without naming anything from it", () => {
		const file = join(mkdtempSync(join(tmpdir(), "deps-")), "sideEffect.mts");
		writeFileSync(file, 'import "express";\nimport "./local.mjs";\n');
		expect(valueImports(file)).toEqual(["express", "./local.mjs"]);
		expect(allImports(file)).toEqual(["express", "./local.mjs"]);
	});

	it("sees a dynamic import() with a literal specifier, which loads a module when it runs", () => {
		const file = join(mkdtempSync(join(tmpdir(), "deps-")), "dynamic.mts");
		writeFileSync(
			file,
			'export const load = async () => (await import("express")).default;\n' +
				'const lazy = () => import( "./local.mjs" );\n' +
				'const data = () => import("./data.json", { with: { type: "json" } });\n',
		);
		expect(valueImports(file)).toEqual(["express", "./local.mjs", "./data.json"]);
		expect(allImports(file)).toEqual(["express", "./local.mjs", "./data.json"]);
	});
});
