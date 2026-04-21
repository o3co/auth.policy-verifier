// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { cpSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
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
	const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);
	cpSync(TEMPLATES_DIR, targetDir, {
		recursive: true,
		filter: (source) => {
			const segments = source.split(sep);
			return !segments.some((s) => EXCLUDED_DIRS.has(s));
		},
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

/**
 * CLI entry point: reads the project name from argv, validates it as an
 * unscoped npm package name, ensures the target directory does not exist,
 * and scaffolds the template. Exits with non-zero on any validation failure.
 */
export const main = (): void => {
	const args = process.argv.slice(2);
	const projectName = args[0];

	if (!projectName) {
		console.error("Usage: create-o3co-policy-verifier <project-name>");
		process.exit(1);
	}

	// Project name is used as a directory name and npm package name (unscoped).
	// Reject path separators, dot segments, and invalid characters.
	const validName = /^[a-z0-9][a-z0-9-._~]*$/;
	if (
		projectName.length > 214 ||
		projectName === "." ||
		projectName === ".." ||
		!validName.test(projectName)
	) {
		console.error(
			"Error: Project name must be a valid unscoped npm package name (lowercase, no spaces or path separators).",
		);
		process.exit(1);
	}

	const targetDir = resolve(process.cwd(), projectName);

	if (existsSync(targetDir)) {
		console.error(`Error: Directory '${projectName}' already exists.`);
		process.exit(1);
	}

	console.log(`Creating ${projectName}...`);
	scaffold(targetDir, projectName);

	console.log(`\nDone! Created ${projectName} at ${targetDir}`);
	console.log(`\nNext steps:`);
	console.log(`  cd ${projectName}`);
	console.log("  npm install");
	console.log("  npm run debug");
};
