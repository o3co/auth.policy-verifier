// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	generateLockfile,
	isTemplateEntryIncluded,
	isValidDirName,
	isValidProjectName,
	main,
	scaffold,
} from "../index.mjs";

// generateLockfile shells out to a package manager. Every test in this file
// drives that boundary through the mock: the suite must never touch the
// network, and the monorepo's own template pins `workspace:*` placeholders
// that no registry can resolve anyway.
const { spawnSyncMock } = vi.hoisted(() => ({ spawnSyncMock: vi.fn() }));
vi.mock("node:child_process", () => ({ spawnSync: spawnSyncMock }));

const enoent = (bin: string) => Object.assign(new Error(`spawn ${bin} ENOENT`), { code: "ENOENT" });

beforeEach(() => {
	spawnSyncMock.mockReset();
	spawnSyncMock.mockReturnValue({ status: 0, signal: null });
});

describe("scaffold", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "create-policy-verifier-test-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("copies template files to target directory", () => {
		const targetDir = join(tempDir, "verifier");
		scaffold(targetDir, "verifier");

		expect(existsSync(join(targetDir, "package.json"))).toBe(true);
		expect(existsSync(join(targetDir, "tsconfig.json"))).toBe(true);
		expect(existsSync(join(targetDir, "src", "main.mts"))).toBe(true);
		expect(existsSync(join(targetDir, "config", "application.conf"))).toBe(true);
		expect(existsSync(join(targetDir, "config", "development.conf"))).toBe(true);
		expect(existsSync(join(targetDir, "config", "production.conf"))).toBe(true);
	});

	it("rewrites package.json name to project name", () => {
		const targetDir = join(tempDir, "verifier");
		scaffold(targetDir, "verifier");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.name).toBe("verifier");
	});

	it("replaces all workspace:* dependencies with caret versions", () => {
		const targetDir = join(tempDir, "verifier");
		scaffold(targetDir, "verifier");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));

		for (const section of ["dependencies", "devDependencies", "peerDependencies"]) {
			const deps = pkg[section];
			if (!deps) continue;
			for (const [name, version] of Object.entries(deps)) {
				expect(version, `${section}.${name} should not be workspace:*`).not.toBe("workspace:*");
			}
		}
	});

	it("removes private field from package.json", () => {
		const targetDir = join(tempDir, "verifier");
		scaffold(targetDir, "verifier");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.private).toBeUndefined();
	});

	it("writes scoped project name verbatim into package.json", () => {
		const targetDir = join(tempDir, "auth.policy-verifier");
		scaffold(targetDir, "@piratis-blossoms/auth.policy-verifier");

		const pkg = JSON.parse(readFileSync(join(targetDir, "package.json"), "utf-8"));
		expect(pkg.name).toBe("@piratis-blossoms/auth.policy-verifier");
	});
});

describe("isTemplateEntryIncluded", () => {
	// The scaffolder is installed under node_modules by `npm create` / npx, so
	// every source path it copies from contains a "node_modules" segment. The
	// exclusion has to be judged relative to the template root, or it rejects
	// the entire template and the scaffold produces nothing.
	const installed = "/home/u/.npm/_npx/abc/node_modules/@o3co/create-auth-policy-verifier";
	const root = `${installed}/templates/standalone`;

	it("includes template files when the install path contains node_modules", () => {
		expect(isTemplateEntryIncluded(root, `${root}/package.json`)).toBe(true);
		expect(isTemplateEntryIncluded(root, `${root}/src/main.mts`)).toBe(true);
		expect(isTemplateEntryIncluded(root, `${root}/config/application.conf`)).toBe(true);
	});

	it("includes the template root itself", () => {
		expect(isTemplateEntryIncluded(root, root)).toBe(true);
	});

	it("still excludes node_modules and dist inside the template", () => {
		expect(isTemplateEntryIncluded(root, `${root}/node_modules`)).toBe(false);
		expect(isTemplateEntryIncluded(root, `${root}/node_modules/express/index.js`)).toBe(false);
		expect(isTemplateEntryIncluded(root, `${root}/dist`)).toBe(false);
		expect(isTemplateEntryIncluded(root, `${root}/dist/main.mjs`)).toBe(false);
	});

	it("does not confuse a name that merely contains an excluded word", () => {
		expect(isTemplateEntryIncluded(root, `${root}/src/dist-helpers.mts`)).toBe(true);
	});
});

describe("generateLockfile", () => {
	const LOCKFILE_ARGS = ["install", "--lockfile-only", "--ignore-workspace"];

	it("resolves the dependency graph with pnpm in the target directory", () => {
		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(true);
		expect(spawnSyncMock).toHaveBeenCalledTimes(1);
		const [bin, args, options] = spawnSyncMock.mock.calls[0];
		expect(bin).toBe("pnpm");
		expect(args).toEqual(LOCKFILE_ARGS);
		expect(options.cwd).toBe("/tmp/target");
		// A scaffolded project must get its OWN lockfile even when the target
		// directory happens to sit inside somebody else's pnpm workspace.
		expect(args).toContain("--ignore-workspace");
	});

	it("falls back to corepack when pnpm is not on PATH", () => {
		spawnSyncMock
			.mockReturnValueOnce({ error: enoent("pnpm") })
			.mockReturnValueOnce({ status: 0, signal: null });

		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(true);
		expect(spawnSyncMock).toHaveBeenCalledTimes(2);
		const [bin, args] = spawnSyncMock.mock.calls[1];
		expect(bin).toBe("corepack");
		expect(args).toEqual(["pnpm", ...LOCKFILE_ARGS]);
	});

	it("does not retry with corepack when pnpm ran and failed", () => {
		// A non-zero exit means resolution failed (offline, private registry,
		// unpublished version). Running the same resolution through a second
		// launcher would fail identically and only doubles the wait.
		spawnSyncMock.mockReturnValue({ status: 1, signal: null });

		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(false);
		expect(spawnSyncMock).toHaveBeenCalledTimes(1);
	});

	it("does not retry with corepack when launching pnpm failed for any other reason", () => {
		// ENOENT is "this binary is not on PATH", which the next launcher can
		// answer. EACCES is not: pnpm IS there and could not be executed, and
		// retrying would both hide that and hand the operator the wrong
		// instruction ("install pnpm") for a permissions problem.
		spawnSyncMock.mockReturnValue({
			error: Object.assign(new Error("spawn pnpm EACCES"), { code: "EACCES" }),
		});

		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(false);
		expect(spawnSyncMock).toHaveBeenCalledTimes(1);
		if (result.ok) throw new Error("unreachable");
		expect(result.reason).toMatch(/EACCES/);
	});

	it("reports failure when no package manager can be launched", () => {
		spawnSyncMock
			.mockReturnValueOnce({ error: enoent("pnpm") })
			.mockReturnValueOnce({ error: enoent("corepack") });

		const result = generateLockfile("/tmp/target");

		expect(result.ok).toBe(false);
		if (result.ok) throw new Error("unreachable");
		expect(result.reason).toMatch(/pnpm/);
	});
});

describe("isValidProjectName", () => {
	it.each([
		["my-verifier"],
		["auth.policy-verifier"],
		["a"],
		["foo_bar~baz.1"],
		["@piratis-blossoms/auth.policy-verifier"],
		["@foo-bar/baz_qux~1"],
	])("accepts %s", (name) => {
		expect(isValidProjectName(name)).toBe(true);
	});

	it.each([
		[""],
		["."],
		[".."],
		["UPPER"],
		["with space"],
		["with/slash"],
		["with\\back"],
		["@"],
		["@/"],
		["@scope"],
		["@/pkg"],
		["@scope/"],
		["@scope//pkg"],
		["@SCOPE/pkg"],
		["a".repeat(215)],
	])("rejects %s", (name) => {
		expect(isValidProjectName(name)).toBe(false);
	});
});

describe("isValidDirName", () => {
	it.each([["my-verifier"], ["auth.policy-verifier"], ["a"], ["foo_bar~baz.1"]])(
		"accepts %s",
		(name) => {
			expect(isValidDirName(name)).toBe(true);
		},
	);

	it.each([
		[""],
		["."],
		[".."],
		["@scope/pkg"],
		["with/slash"],
		["with\\back"],
		["@piratis-blossoms"],
		["UPPER"],
		["a".repeat(215)],
	])("rejects %s", (name) => {
		expect(isValidDirName(name)).toBe(false);
	});
});

describe("main (argv parsing and directory derivation)", () => {
	let cwdBackup: string;
	let workdir: string;
	let argvBackup: string[];

	beforeEach(() => {
		cwdBackup = process.cwd();
		workdir = mkdtempSync(join(tmpdir(), "create-policy-verifier-main-"));
		process.chdir(workdir);
		argvBackup = process.argv;
	});

	afterEach(() => {
		process.chdir(cwdBackup);
		process.argv = argvBackup;
		rmSync(workdir, { recursive: true, force: true });
	});

	const runMain = (args: string[]): { exitCode: number | null; stderr: string; stdout: string } => {
		process.argv = ["node", "cli", ...args];
		const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			throw new Error(`__exit__:${code ?? 0}`);
		}) as never);
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		let exitCode: number | null = 0;
		try {
			main();
		} catch (e) {
			const m = /__exit__:(\d+)/.exec((e as Error).message);
			exitCode = m ? Number(m[1]) : null;
		}
		const stderr = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
		const stdout = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
		exitSpy.mockRestore();
		errSpy.mockRestore();
		logSpy.mockRestore();
		return { exitCode, stderr, stdout };
	};

	it("unscoped name: dir = name, pkg.name = name", () => {
		const r = runMain(["my-verifier"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "my-verifier", "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-verifier");
	});

	it("scoped name: dir = pkg part, pkg.name = full scoped", () => {
		const r = runMain(["@piratis-blossoms/auth.policy-verifier"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(
			readFileSync(join(workdir, "auth.policy-verifier", "package.json"), "utf-8"),
		);
		expect(pkg.name).toBe("@piratis-blossoms/auth.policy-verifier");
	});

	it("scoped name with --dir <val>: dir = val, pkg.name = full scoped", () => {
		const r = runMain(["@piratis-blossoms/auth.policy-verifier", "--dir", "verifier"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "verifier", "package.json"), "utf-8"));
		expect(pkg.name).toBe("@piratis-blossoms/auth.policy-verifier");
	});

	it("scoped name with --dir=<val>: dir = val, pkg.name = full scoped", () => {
		const r = runMain(["@piratis-blossoms/auth.policy-verifier", "--dir=verifier2"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "verifier2", "package.json"), "utf-8"));
		expect(pkg.name).toBe("@piratis-blossoms/auth.policy-verifier");
	});

	it("unscoped name with --dir <val>: dir = val, pkg.name = unscoped", () => {
		const r = runMain(["my-verifier", "--dir", "custom"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "custom", "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-verifier");
	});

	it("flags before positional: --dir custom my-verifier", () => {
		const r = runMain(["--dir", "custom", "my-verifier"]);
		expect(r.exitCode).toBe(0);
		const pkg = JSON.parse(readFileSync(join(workdir, "custom", "package.json"), "utf-8"));
		expect(pkg.name).toBe("my-verifier");
	});

	it.each([
		{ case: "no args", args: [] },
		{ case: "two positionals", args: ["foo", "bar"] },
		{ case: "dot", args: ["."] },
		{ case: "dotdot", args: [".."] },
		{ case: "backslash in name", args: ["back\\slash"] },
		{ case: "empty scope", args: ["@/pkg"] },
		{ case: "empty pkg", args: ["@scope/"] },
		{ case: "double slash", args: ["@scope//pkg"] },
		{ case: "name too long", args: ["a".repeat(215)] },
		{ case: "--dir invalid (dot)", args: ["foo", "--dir", "."] },
		{ case: "--dir invalid (slash)", args: ["foo", "--dir", "a/b"] },
		{ case: "--dir invalid (at)", args: ["foo", "--dir", "@foo"] },
		{ case: "--dir invalid (back)", args: ["foo", "--dir", "a\\b"] },
		{ case: "--dir empty space form", args: ["foo", "--dir", ""] },
		{ case: "--dir empty equals form", args: ["foo", "--dir="] },
		{ case: "--dir missing value", args: ["foo", "--dir"] },
		{ case: "--dir duplicated", args: ["foo", "--dir", "a", "--dir", "b"] },
		{ case: "unknown flag", args: ["foo", "--unknown"] },
		{ case: "literal double-dash", args: ["foo", "--"] },
	])("rejects: $case", ({ args }) => {
		const r = runMain(args);
		expect(r.exitCode).toBe(1);
		expect(r.stderr.length).toBeGreaterThan(0);
	});

	it("target directory already exists", () => {
		mkdirSync(join(workdir, "foo"));
		const r = runMain(["foo"]);
		expect(r.exitCode).toBe(1);
		expect(r.stderr.length).toBeGreaterThan(0);
	});
});

describe("main (scaffold-time lockfile)", () => {
	let cwdBackup: string;
	let workdir: string;
	let argvBackup: string[];

	beforeEach(() => {
		cwdBackup = process.cwd();
		workdir = mkdtempSync(join(tmpdir(), "create-policy-verifier-lock-"));
		process.chdir(workdir);
		argvBackup = process.argv;
	});

	afterEach(() => {
		process.chdir(cwdBackup);
		process.argv = argvBackup;
		rmSync(workdir, { recursive: true, force: true });
	});

	const runMain = (args: string[]): { exitCode: number | null; stderr: string } => {
		process.argv = ["node", "cli", ...args];
		const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			throw new Error(`__exit__:${code ?? 0}`);
		}) as never);
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		let exitCode: number | null = 0;
		try {
			main();
		} catch (e) {
			const m = /__exit__:(\d+)/.exec((e as Error).message);
			exitCode = m ? Number(m[1]) : null;
		}
		const stderr = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
		exitSpy.mockRestore();
		errSpy.mockRestore();
		logSpy.mockRestore();
		return { exitCode, stderr };
	};

	it("generates the lockfile in the scaffolded directory", () => {
		// The Dockerfile installs with --frozen-lockfile, so the scaffold owes
		// the new project a pnpm-lock.yaml it can commit.
		const r = runMain(["my-verifier"]);

		expect(r.exitCode).toBe(0);
		expect(spawnSyncMock).toHaveBeenCalledTimes(1);
		const [, , options] = spawnSyncMock.mock.calls[0];
		// realpath: main() derives the target from process.cwd(), and on macOS
		// the temp directory reaches it through the /var -> /private/var symlink.
		expect(options.cwd).toBe(join(realpathSync(workdir), "my-verifier"));
	});

	it("resolves against the rewritten package.json, not the template's", () => {
		// scaffold() replaces every workspace:* with a published version. The
		// lockfile has to be produced after that rewrite or it would pin
		// specifiers that no registry serves.
		let pkgAtSpawn: Record<string, unknown> | undefined;
		spawnSyncMock.mockImplementation((_bin, _args, options) => {
			pkgAtSpawn = JSON.parse(readFileSync(join(options.cwd as string, "package.json"), "utf-8"));
			return { status: 0, signal: null };
		});

		expect(runMain(["my-verifier"]).exitCode).toBe(0);

		const deps = (pkgAtSpawn?.dependencies ?? {}) as Record<string, string>;
		expect(Object.keys(deps).length).toBeGreaterThan(0);
		expect(Object.values(deps)).not.toContain("workspace:*");
		expect(pkgAtSpawn?.name).toBe("my-verifier");
	});

	it("skips generation with --no-lockfile", () => {
		const r = runMain(["my-verifier", "--no-lockfile"]);

		expect(r.exitCode).toBe(0);
		expect(existsSync(join(workdir, "my-verifier", "package.json"))).toBe(true);
		expect(spawnSyncMock).not.toHaveBeenCalled();
	});

	it("warns but still succeeds when the lockfile cannot be generated", () => {
		// Offline, private registry, no pnpm: the project is still usable, so
		// the scaffold must not fail — but the operator has to be told, because
		// `docker build` needs the lockfile.
		spawnSyncMock.mockReturnValue({ status: 1, signal: null });

		const r = runMain(["my-verifier"]);

		expect(r.exitCode).toBe(0);
		expect(existsSync(join(workdir, "my-verifier", "package.json"))).toBe(true);
		expect(r.stderr).toMatch(/pnpm install/);
		expect(r.stderr).toMatch(/pnpm-lock\.yaml/);
	});
});
