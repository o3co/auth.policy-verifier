// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { checkParsePolicySet } from "@cedar-policy/cedar-wasm/nodejs";

/** Where a policy set came from, for boot-time error messages. */
export interface PolicySource {
	/** Concatenated Cedar policy text, ready for `preparsePolicySet`. */
	text: string;
	/** Human description of the source (`inline` or the resolved directory). */
	description: string;
}

/**
 * Loads the Cedar policy text a `CedarPolicyRuleCollector` evaluates.
 *
 * Exactly one of `policyDir` / `policies` must be set. `policyDir` is the
 * intended shape: the `*.cedar` files in that directory (sorted by name,
 * concatenated) are byte-identical to what a Cedar agent would load, so the
 * corpus stays lift-and-shift portable and the official `cedar` CLI can
 * validate the same files in CI. `policies` inlines a small set directly in
 * config.
 *
 * Every file is parse-checked individually before the set is accepted, so a
 * syntax error is reported against the file that contains it rather than
 * against an offset into an invisible concatenation. All of this runs at boot,
 * inside the collector factory: a broken policy set refuses to start, it does
 * not serve denials (two-boundary validation — config is checked before the
 * first request, here because file contents cannot be checked by the config
 * schema).
 *
 * A directory with zero `.cedar` files is allowed and yields the empty policy
 * set: that is migration step one — the collector mounted, abstaining on every
 * request, behavior unchanged until the first policy lands.
 *
 * Relative paths resolve against the working directory, matching how the
 * standalone template addresses its `config/` tree.
 */
export function loadPolicySource(config: {
	policyDir?: unknown;
	policies?: unknown;
}): PolicySource {
	const { policyDir, policies } = config;
	if (policyDir !== undefined && policies !== undefined) {
		throw new Error(
			"CedarPolicyRuleCollector: policyDir and policies are mutually exclusive — configure one",
		);
	}

	if (policies !== undefined) {
		if (typeof policies !== "string") {
			throw new Error(
				`CedarPolicyRuleCollector: policies must be a string, got ${typeof policies}`,
			);
		}
		assertParses(policies, "policies (inline)");
		return { text: policies, description: "inline policies" };
	}

	if (policyDir === undefined) {
		throw new Error("CedarPolicyRuleCollector: one of policyDir or policies is required");
	}
	if (typeof policyDir !== "string" || policyDir.length === 0) {
		throw new Error(
			`CedarPolicyRuleCollector: policyDir must be a non-empty string, got ${typeof policyDir}`,
		);
	}

	const dir = resolve(policyDir);
	let names: string[];
	try {
		names = readdirSync(dir);
	} catch (cause) {
		throw new Error(`CedarPolicyRuleCollector: cannot read policyDir "${dir}": ${message(cause)}`);
	}

	const files = names.filter((name) => name.endsWith(".cedar")).sort();
	const parts: string[] = [];
	for (const name of files) {
		const path = resolve(dir, name);
		let text: string;
		try {
			text = readFileSync(path, "utf8");
		} catch (cause) {
			throw new Error(`CedarPolicyRuleCollector: cannot read "${path}": ${message(cause)}`);
		}
		assertParses(text, path);
		parts.push(text);
	}

	return { text: parts.join("\n"), description: dir };
}

/** Parse-checks one policy text, naming its source on failure. */
function assertParses(text: string, source: string): void {
	const answer = checkParsePolicySet({ staticPolicies: text });
	if (answer.type === "failure") {
		const details = answer.errors.map((error) => error.message).join("; ");
		throw new Error(`CedarPolicyRuleCollector: ${source} failed to parse: ${details}`);
	}
}

function message(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
