// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { cpSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = resolve(__dirname, "../templates/standalone");

/**
 * Reads the embedded `versions.json` produced by the prebuild script. Returns
 * an empty map if the file is absent (e.g. running from source without
 * prebuild), so callers must treat "not found" as a separate branch.
 */
const getPackageVersions = (): Record<string, string> => {
	const versionFile = resolve(__dirname, "../templates/versions.json");
	if (existsSync(versionFile)) {
		return JSON.parse(readFileSync(versionFile, "utf-8"));
	}
	return {};
};

/** Directories that are build output inside the template, never scaffolded. */
const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);

/**
 * Decides whether one entry of the template tree is copied into a new project.
 *
 * The exclusion is judged on the path RELATIVE to the template root, which is
 * the whole point: the scaffolder ships inside `node_modules` whenever it is
 * run the documented way (`npm create`, `npx`), so every absolute source path
 * it copies from contains a `node_modules` segment. Matching against the
 * absolute path therefore rejected the entire template and produced an empty
 * project directory — the scaffolder only ever worked from a source checkout.
 */
export const isTemplateEntryIncluded = (templatesDir: string, source: string): boolean => {
	const rel = relative(templatesDir, source);
	if (rel === "") return true;
	return !rel.split(sep).some((segment) => EXCLUDED_DIRS.has(segment));
};

const UNSCOPED_NAME_RE = /^[a-z0-9][a-z0-9-._~]*$/;
const SCOPED_NAME_RE = /^@[a-z0-9][a-z0-9-._~]*\/[a-z0-9][a-z0-9-._~]*$/;
const MAX_NAME_LEN = 214;

export const isValidProjectName = (name: string): boolean => {
	if (name.length === 0 || name.length > MAX_NAME_LEN) return false;
	if (name === "." || name === "..") return false;
	return UNSCOPED_NAME_RE.test(name) || SCOPED_NAME_RE.test(name);
};

export const isValidDirName = (name: string): boolean => {
	if (name.length === 0 || name.length > MAX_NAME_LEN) return false;
	if (name === "." || name === "..") return false;
	return UNSCOPED_NAME_RE.test(name);
};

/**
 * Copies the bundled standalone template into `targetDir`, rewrites
 * `package.json` with the new `projectName`, and replaces every `workspace:*`
 * dependency with the concrete published version from `versions.json`.
 *
 * Throws if the template directory is missing (unprebuilt) or if any
 * workspace dependency is not pinned in `versions.json`.
 */
export const scaffold = (targetDir: string, projectName: string): void => {
	if (!existsSync(TEMPLATES_DIR)) {
		throw new Error(
			`Template directory not found at ${TEMPLATES_DIR}. If developing locally, run the prebuild script first.`,
		);
	}

	// Copy template to target
	cpSync(TEMPLATES_DIR, targetDir, {
		recursive: true,
		filter: (source) => isTemplateEntryIncluded(TEMPLATES_DIR, source),
	});

	// Rewrite package.json
	const pkgPath = resolve(targetDir, "package.json");
	const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
	pkg.name = projectName;
	delete pkg.private;

	// Replace all workspace:* references with per-package published versions
	const versions = getPackageVersions();
	for (const section of ["dependencies", "devDependencies", "peerDependencies"] as const) {
		const deps = pkg[section];
		if (!deps) continue;
		for (const [name, version] of Object.entries(deps)) {
			if (version === "workspace:*") {
				const resolved = versions[name];
				if (!resolved) {
					throw new Error(
						`Cannot resolve version for workspace dependency "${name}". Ensure versions.json includes this package.`,
					);
				}
				deps[name] = `^${resolved}`;
			}
		}
	}

	writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
};

/** Outcome of the scaffold-time lockfile generation. */
export type LockfileResult =
	| { readonly ok: true; readonly command: string }
	| { readonly ok: false; readonly reason: string };

/**
 * Arguments that make pnpm resolve the dependency graph and write
 * `pnpm-lock.yaml` without linking `node_modules` or running any lifecycle
 * script. `--ignore-workspace` keeps the new project's lockfile its own even
 * when the target directory happens to sit inside another pnpm workspace.
 */
const LOCKFILE_ARGS = ["install", "--lockfile-only", "--ignore-workspace"] as const;

/**
 * Launchers tried in order. `pnpm` on PATH is the common case; `corepack pnpm`
 * covers a machine that only has Node, and honours the `packageManager` field
 * the template ships.
 *
 * The fallback is narrow on purpose: it applies to `ENOENT` and nothing else,
 * because `ENOENT` is the one failure that means "this binary is not here" and
 * is therefore the only one a different launcher can answer. Any other launch
 * error (`EACCES`, `EPERM`, …) says the binary IS there and could not be run,
 * and a package manager that ran and exited non-zero has already reported that
 * resolution failed — retrying either would hide the real cause behind
 * "package manager missing" and hand the operator the wrong instruction.
 */
const LOCKFILE_LAUNCHERS: readonly (readonly string[])[] = [["pnpm"], ["corepack", "pnpm"]];

/**
 * Generates `pnpm-lock.yaml` inside an already-scaffolded `targetDir`.
 *
 * This is what makes the template's `pnpm install --frozen-lockfile` build
 * possible: the lockfile cannot be shipped with the template, because the
 * template's dependency set does not exist until `scaffold` has replaced every
 * `workspace:*` with a published version. So it is resolved here, once, against
 * the rewritten `package.json`, and the project commits the result.
 *
 * Best-effort by design: it needs a package manager and a reachable registry,
 * and neither is guaranteed on the machine running the scaffolder. Failure is
 * reported, never thrown — the generated project is perfectly usable without
 * it, the operator just has to run `pnpm install` before `docker build`.
 */
export const generateLockfile = (targetDir: string): LockfileResult => {
	const attempts: string[] = [];

	for (const launcher of LOCKFILE_LAUNCHERS) {
		const [bin, ...prefix] = launcher;
		const args = [...prefix, ...LOCKFILE_ARGS];
		const printable = [bin, ...args].join(" ");
		const result = spawnSync(bin, args, {
			cwd: targetDir,
			stdio: "inherit",
			shell: false,
			env: { ...process.env, COREPACK_ENABLE_DOWNLOAD_PROMPT: "0" },
		});

		if (result.error) {
			attempts.push(`${printable}: ${result.error.message}`);
			// Only "not on PATH" is worth asking a different launcher about.
			if ((result.error as NodeJS.ErrnoException).code === "ENOENT") continue;
			break;
		}
		if (result.status === 0) return { ok: true, command: printable };

		const how =
			result.status === null ? `killed by signal ${result.signal}` : `exit code ${result.status}`;
		attempts.push(`${printable}: ${how}`);
		break;
	}

	return { ok: false, reason: attempts.join("; ") };
};

interface ParsedArgs {
	projectName: string;
	dir: string | undefined;
	lockfile: boolean;
}

const parseArgs = (args: string[]): ParsedArgs => {
	const positionals: string[] = [];
	let dir: string | undefined;
	let dirSeen = false;
	let lockfile = true;

	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		if (a === "--dir") {
			if (dirSeen) throw new Error("--dir specified more than once");
			if (i + 1 >= args.length) throw new Error("--dir requires a value");
			dir = args[i + 1];
			dirSeen = true;
			i++;
		} else if (a.startsWith("--dir=")) {
			if (dirSeen) throw new Error("--dir specified more than once");
			dir = a.slice("--dir=".length);
			dirSeen = true;
		} else if (a === "--no-lockfile") {
			lockfile = false;
		} else if (a.startsWith("-")) {
			// Treats `--` and any --unknown as an unknown flag.
			throw new Error(`unknown flag: ${a}`);
		} else {
			positionals.push(a);
		}
	}

	if (positionals.length === 0) throw new Error("missing <project-name>");
	if (positionals.length > 1) throw new Error("too many positional arguments");

	return { projectName: positionals[0], dir, lockfile };
};

const deriveDirName = (projectName: string, dir: string | undefined): string => {
	if (dir !== undefined) return dir;
	if (projectName.startsWith("@")) {
		const pkgPart = projectName.split("/")[1];
		if (!pkgPart) {
			// Unreachable when projectName has passed isValidProjectName (SCOPED_NAME_RE
			// guarantees a non-empty package segment after the single "/"). Guarded here
			// so refactors that reorder validation cannot silently produce undefined.
			throw new Error(`invariant: unvalidated scoped name ${projectName}`);
		}
		return pkgPart;
	}
	return projectName;
};

/**
 * CLI entry point: parses argv, validates project name and optional --dir flag,
 * ensures the target directory does not exist, and scaffolds the template.
 * Exits with non-zero on any validation failure.
 */
export const main = (): void => {
	const args = process.argv.slice(2);

	let parsed: ParsedArgs;
	try {
		parsed = parseArgs(args);
	} catch (e) {
		console.error(`Error: ${(e as Error).message}`);
		console.error(
			"Usage: @o3co/create-auth-policy-verifier <project-name> [--dir <dir-name>] [--no-lockfile]",
		);
		process.exit(1);
	}

	const { projectName, dir, lockfile } = parsed;

	if (!isValidProjectName(projectName)) {
		console.error(
			"Error: <project-name> must be a valid npm package name (scoped like @scope/pkg, or unscoped; max 214 chars; no backslashes; no extra '/' beyond the single scope separator).",
		);
		process.exit(1);
	}

	if (dir !== undefined && !isValidDirName(dir)) {
		console.error(
			"Error: --dir must be a valid unscoped package name (no '/', '\\', '@'; not '.' or '..'; max 214 chars).",
		);
		process.exit(1);
	}

	const dirName = deriveDirName(projectName, dir);
	const targetDir = resolve(process.cwd(), dirName);

	if (existsSync(targetDir)) {
		console.error(`Error: Directory '${dirName}' already exists.`);
		process.exit(1);
	}

	console.log(`Creating ${projectName}...`);
	scaffold(targetDir, projectName);

	let lockfileGenerated = false;
	if (lockfile) {
		console.log("\nResolving dependencies into pnpm-lock.yaml...");
		const result = generateLockfile(targetDir);
		lockfileGenerated = result.ok;
		if (!result.ok) {
			console.error(`\nWarning: could not generate pnpm-lock.yaml (${result.reason}).`);
			console.error(
				`Run 'pnpm install' in ${dirName} and commit pnpm-lock.yaml: the Dockerfile installs with --frozen-lockfile and will not build without it.`,
			);
		}
	}

	console.log(`\nDone! Created ${projectName} at ${targetDir}`);
	if (lockfileGenerated) {
		console.log(
			"\nCommit pnpm-lock.yaml along with the rest: it is what makes 'docker build' reproducible.",
		);
	}
	console.log(`\nNext steps:`);
	console.log(`  cd ${dirName}`);
	console.log("  pnpm install");
	console.log("  pnpm run debug");
};
