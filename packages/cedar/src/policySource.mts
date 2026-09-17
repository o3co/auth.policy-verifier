// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

/** One policy file as read, with where it came from for error messages. */
export interface PolicyFile {
	/**
	 * The file's bare name (`10-permit-eng.cedar`), or `policies` for the
	 * inline set. What the {@link PolicySource.revision | revision} covers
	 * beside the text — never `source`, which is this machine's path.
	 */
	name: string;
	/** The resolved path, or `policies (inline)`. */
	source: string;
	/** The file's Cedar text, unmodified. */
	text: string;
}

/** A policy set as loaded, ready for a `CedarEngine` to parse and compile. */
export interface PolicySource {
	/** Every file, in the order `text` concatenates them. */
	files: readonly PolicyFile[];
	/** The concatenated Cedar policy text. */
	text: string;
	/** Human description of the source (`inline policies` or the resolved directory). */
	description: string;
	/**
	 * Identifies the contents above (#244) — see {@link computePolicyRevision}.
	 * Computed here, once, from the same `files` an engine is handed, so the
	 * reference and what it refers to cannot be read at two different moments.
	 */
	revision: string;
}

/** Versioned, so the preimage can change without an old digest meaning something new. */
const REVISION_PREIMAGE_HEADER = "auth.policy-verifier.cedar/policy-set/v1\n";

/**
 * The reference a decision's provenance names for a loaded policy set (#244):
 * `sha256:` and the lowercase hex SHA-256 of
 *
 * ```text
 * auth.policy-verifier.cedar/policy-set/v1\n
 * <bytes>:<name>,<bytes>:<text>,      ← once per file, in load order
 * ```
 *
 * with `<bytes>` the decimal UTF-8 byte length of what follows it (netstring
 * framing). The notation is the OCI digest grammar, which is the shape core
 * holds a revision to.
 *
 * **What it covers, and why that.** Each file's name and text, in the order
 * they are loaded, and nothing else. The name is in because it is the policy
 * id the http engine gives the agent, so a rename changes what a decision's
 * determining policies are called. The framing is there because the
 * concatenation is not injective — `"X\n" + "Y"` and `"X" + "\nY"` are one
 * `text` and two policy sets. The directory is deliberately out: two replicas
 * mounting the same files at different paths hold the same revision, and a
 * path is not something a decision response may carry.
 *
 * **What it does not cover.** The collector's mapping, `onNoDeterminingPolicy`,
 * the engine and its version, and the attributes a request was decided over
 * all shape an answer too. The revision says which policies were evaluated; it
 * does not promise that evaluating them again gives the same answer.
 *
 * It is the text as decoded that is hashed, because that is what an engine is
 * handed. For a file that is valid UTF-8 that is the file's own bytes.
 */
export function computePolicyRevision(files: readonly Pick<PolicyFile, "name" | "text">[]): string {
	const hash = createHash("sha256").update(REVISION_PREIMAGE_HEADER, "utf8");
	for (const file of files) {
		hash.update(netstring(file.name), "utf8").update(netstring(file.text), "utf8");
	}
	return `sha256:${hash.digest("hex")}`;
}

function netstring(value: string): string {
	return `${Buffer.byteLength(value, "utf8")}:${value},`;
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
 * Reading is this function's whole job; parsing is the engine's. The files
 * are handed over individually (`files`) as well as concatenated (`text`) so
 * that `CedarEngine.load` can parse-check each one and report a syntax error
 * against the file that contains it rather than against an offset into an
 * invisible concatenation. All of this runs at boot, inside the collector
 * factory: a broken policy set refuses to start, it does not serve denials
 * (two-boundary validation — config is checked before the first request, here
 * because file contents cannot be checked by the config schema).
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
		const files = [{ name: "policies", source: "policies (inline)", text: policies }];
		return {
			files,
			text: policies,
			description: "inline policies",
			revision: computePolicyRevision(files),
		};
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

	const files: PolicyFile[] = [];
	for (const name of names.filter((name) => name.endsWith(".cedar")).sort()) {
		const path = resolve(dir, name);
		try {
			files.push({ name, source: path, text: readFileSync(path, "utf8") });
		} catch (cause) {
			throw new Error(`CedarPolicyRuleCollector: cannot read "${path}": ${message(cause)}`);
		}
	}

	return {
		files,
		text: files.map((file) => file.text).join("\n"),
		description: dir,
		revision: computePolicyRevision(files),
	};
}

function message(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
