// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The official `cedar` CLI (cedar-policy-cli), driven as the reference
 * evaluator for the CLI-equivalence suite (#198, #284): locating the binary, reading
 * its version, running `cedar authorize --verbose`, and reading its answer back.
 *
 * The CLI has no machine-readable answer — `--error-format json` covers its
 * own failures, not the decision — so its text is parsed, strictly: a line the
 * parser has not seen is an error, never skipped, because a misread answer
 * would make two evaluators look equivalent when they are not. The format is
 * pinned by `cedar-cli-output.test.mts` against the literal output of
 * cedar-policy-cli 4.13.0 and 2.5.0; a CLI that prints differently fails
 * there first.
 */

import { spawnSync } from "node:child_process";

/** What `cedar authorize --verbose` answered, read back. */
export interface CliAnswer {
	decision: "allow" | "deny";
	/** The determining policies, in the order the CLI listed them. */
	reason: string[];
	/** The evaluation errors, each with the policy that raised it. */
	errors: Array<{ policyId: string; message: string }>;
}

/** Where the CLI is: `CEDAR_CLI`, else `cedar` on the PATH, else nowhere. */
export function locateCedarCli(env: NodeJS.ProcessEnv = process.env): string | undefined {
	if (env.CEDAR_CLI !== undefined && env.CEDAR_CLI.length > 0) return env.CEDAR_CLI;
	// No `sh` (Windows): no CLI found, rather than a suite that fails to load.
	const which = spawnSync("sh", ["-c", "command -v cedar"], { encoding: "utf8" });
	const found = which.stdout?.trim() ?? "";
	return which.status === 0 && found.length > 0 ? found : undefined;
}

/** Reads `cedar --version`: `cedar-policy-cli 4.13.0` → `4.13.0`. */
export function parseCliVersion(output: string): string {
	const match = /^cedar-policy-cli (\d+\.\d+\.\d+)\s*$/.exec(output);
	if (match === null) {
		throw new Error(`not a cedar-policy-cli version: ${JSON.stringify(output)}`);
	}
	return match[1];
}

/** The version of the CLI at `cli`. */
export function cedarCliVersion(cli: string): string {
	const run = spawnSync(cli, ["--version"], { encoding: "utf8" });
	if (run.status !== 0) {
		throw new Error(
			`${cli} --version failed (exit ${run.status}): ${run.error?.message ?? run.stderr}`,
		);
	}
	return parseCliVersion(run.stdout);
}

/** The files one `cedar authorize` call reads. */
export interface AuthorizeFiles {
	policies: string;
	entities: string;
	/** `{ principal, action, resource, context }`, the uids in Cedar syntax. */
	request: string;
}

/**
 * Runs `cedar authorize --verbose` and reads its answer. The CLI exits 0 on an
 * allow and 2 on a deny; anything else is the CLI failing, and throws.
 */
export function cedarAuthorize(cli: string, files: AuthorizeFiles): CliAnswer {
	const run = spawnSync(
		cli,
		[
			"authorize",
			"--policies",
			files.policies,
			"--entities",
			files.entities,
			"--request-json",
			files.request,
			"--verbose",
			"--error-format",
			"plain",
		],
		{ encoding: "utf8" },
	);
	if (run.status !== 0 && run.status !== 2) {
		throw new Error(
			`cedar authorize failed (exit ${run.status}): ${run.error?.message ?? (run.stderr || run.stdout)}`,
		);
	}
	const answer = parseAuthorizeOutput(run.stdout);
	const expected = answer.decision === "allow" ? 0 : 2;
	if (run.status !== expected) {
		throw new Error(`cedar authorize printed ${answer.decision} but exited ${run.status}`);
	}
	return answer;
}

const DETERMINED_BY = "note: this decision was due to the following policies:";
const NONE_APPLIED = "note: no policies applied to this request";
/**
 * An evaluation error: `error while evaluating policy` in cedar-policy-cli 4.x,
 * `error occurred while evaluating policy` in 2.5 — and in cedar-agent 0.2.2's
 * own error strings, which carry its Cedar's wording (#284).
 */
export const EVALUATION_ERROR = /^error (?:occurred )?while evaluating policy `([^`]+)`: (.*)$/;

/** Reads `cedar authorize --verbose` output — see the header for why strictly. */
export function parseAuthorizeOutput(output: string): CliAnswer {
	const lines = output.split("\n");
	let index = lines.findIndex((line) => line.trim().length > 0);
	const verdict = index === -1 ? undefined : lines[index].trim();
	if (verdict !== "ALLOW" && verdict !== "DENY") {
		throw new Error(`cedar authorize printed no decision: ${JSON.stringify(output)}`);
	}
	const answer: CliAnswer = {
		decision: verdict === "ALLOW" ? "allow" : "deny",
		reason: [],
		errors: [],
	};
	let listing = false;
	for (index++; index < lines.length; index++) {
		const line = lines[index];
		if (line.trim().length === 0) {
			listing = false;
			continue;
		}
		if (listing && line.startsWith("  ")) {
			// The CLI prints `  {id}`: the indent is its own, anything after it the id's.
			answer.reason.push(line.slice(2));
			continue;
		}
		const error = EVALUATION_ERROR.exec(line);
		if (error !== null) {
			answer.errors.push({ policyId: error[1], message: error[2] });
			continue;
		}
		if (line === DETERMINED_BY) {
			listing = true;
			continue;
		}
		if (line === NONE_APPLIED) continue;
		throw new Error(
			`cedar authorize printed a line this suite cannot read: ${JSON.stringify(line)}`,
		);
	}
	return answer;
}
