// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { POLICY_REVISION_PATTERN } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { CedarEngineError } from "../engine.mjs";
import * as cedar from "../index.mjs";
import {
	computePolicyRevision,
	loadPolicySource,
	namePolicies,
	type PolicyFile,
	policyIdsOf,
} from "../policySource.mjs";

/** A fresh directory holding exactly these files. */
function policyDir(files: Record<string, string>): string {
	const dir = mkdtempSync(join(tmpdir(), "cedar-policies-"));
	for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
	return dir;
}

describe("loadPolicySource", () => {
	it("concatenates *.cedar files in name order and ignores other files", () => {
		const dir = mkdtempSync(join(tmpdir(), "cedar-policies-"));
		writeFileSync(join(dir, "20-forbid.cedar"), "forbid(principal, action, resource);\n");
		writeFileSync(join(dir, "10-permit.cedar"), "permit(principal, action, resource);\n");
		writeFileSync(join(dir, "README.md"), "not a policy");

		const source = loadPolicySource({ policyDir: dir });
		expect(source.text.indexOf("permit")).toBeLessThan(source.text.indexOf("forbid"));
		expect(source.text).not.toContain("not a policy");
		// Each file is also handed over on its own, so an engine can name the
		// one a syntax error is in; `description` is the resolved directory.
		expect(source.files.map((file) => file.source)).toEqual([
			join(dir, "10-permit.cedar"),
			join(dir, "20-forbid.cedar"),
		]);
		expect(source.description).toBe(dir);
	});

	it("does not parse — an unparseable file is the engine's to refuse", () => {
		const dir = mkdtempSync(join(tmpdir(), "cedar-policies-"));
		writeFileSync(join(dir, "broken.cedar"), "permit(when;\n");
		expect(loadPolicySource({ policyDir: dir }).files).toEqual([
			{ name: "broken.cedar", source: join(dir, "broken.cedar"), text: "permit(when;\n" },
		]);
	});

	it("wraps inline policies as one file named for the config key", () => {
		const source = loadPolicySource({ policies: "permit(principal, action, resource);" });
		expect(source).toEqual({
			files: [
				{
					name: "policies",
					source: "policies (inline)",
					text: "permit(principal, action, resource);",
				},
			],
			text: "permit(principal, action, resource);",
			description: "inline policies",
			revision: computePolicyRevision(source.files),
		});
	});

	it("allows a directory with zero policies — migration step one", () => {
		const dir = mkdtempSync(join(tmpdir(), "cedar-policies-"));
		const source = loadPolicySource({ policyDir: dir });
		expect(source.text).toBe("");
		expect(source.files).toEqual([]);
	});

	it("throws on an unreadable directory", () => {
		expect(() => loadPolicySource({ policyDir: "/nonexistent/cedar-policies" })).toThrow(
			/cannot read policyDir/,
		);
	});
});

/*
 * #244: the revision identifies the policy CONTENTS that were loaded — not
 * where they were loaded from, and not when. It is what a decision's
 * provenance names, so two replicas holding the same files must agree on it
 * and an edit that keeps every policy id must change it.
 */
describe("loadPolicySource — the policy revision", () => {
	const PERMIT = "permit(principal, action, resource);\n";
	const FORBID = "forbid(principal, action, resource);\n";

	it("is a sha256 reference in the shape core carries", () => {
		const { revision } = loadPolicySource({ policyDir: policyDir({ "10-permit.cedar": PERMIT }) });
		expect(revision).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(revision).toMatch(POLICY_REVISION_PATTERN);
	});

	it("is the documented digest — derived here independently, so the algorithm is pinned", () => {
		// sha256 over a versioned header, then each file in load order as two
		// netstrings: `<bytes>:<name>,<bytes>:<text>,`. Byte lengths, not
		// character counts — the policy below is not ASCII.
		const files = {
			"10-permit.cedar": PERMIT,
			"20-名前.cedar": "// 日本語\nforbid(principal, action, resource);",
		};
		const netstring = (value: string) => `${Buffer.byteLength(value, "utf8")}:${value},`;
		const preimage =
			"auth.policy-verifier.cedar/policy-set/v1\n" +
			Object.entries(files)
				.map(([name, text]) => netstring(name) + netstring(text))
				.join("");
		const expected = `sha256:${createHash("sha256").update(preimage, "utf8").digest("hex")}`;

		expect(loadPolicySource({ policyDir: policyDir(files) }).revision).toBe(expected);
	});

	it("matches known answers computed outside this codebase", () => {
		// `printf '<preimage>' | shasum -a 256`, from the algorithm as documented.
		// The case above re-derives the digest in the test; these are literals,
		// so the implementation and its derivation cannot drift together.
		expect(computePolicyRevision([])).toBe(
			"sha256:27213d8c5fbd672a1b3d878f69e627fb2bd116415ecb1a15259d09102d519299",
		);
		expect(
			computePolicyRevision([{ name: "policies", text: "permit(principal, action, resource);" }]),
		).toBe("sha256:b7fa207de93d9b78564eac261a491cbb92e2bce4ce67827c1b0757df844193af");
	});

	it("is the package's to compute for a directory — CI compares it with what production reports", () => {
		const dir = policyDir({ "10-permit.cedar": PERMIT });
		expect(cedar.loadPolicySource({ policyDir: dir }).revision).toBe(
			cedar.computePolicyRevision([{ name: "10-permit.cedar", text: PERMIT }]),
		);
	});

	it("is the same for the same files in a different directory", () => {
		const files = { "10-permit.cedar": PERMIT, "20-forbid.cedar": FORBID };
		const one = loadPolicySource({ policyDir: policyDir(files) });
		const other = loadPolicySource({ policyDir: policyDir(files) });
		expect(one.description).not.toBe(other.description);
		expect(one.revision).toBe(other.revision);
	});

	it("changes when a policy's contents change under the same file name", () => {
		const before = loadPolicySource({ policyDir: policyDir({ "10-rule.cedar": PERMIT }) });
		const after = loadPolicySource({ policyDir: policyDir({ "10-rule.cedar": FORBID }) });
		expect(after.revision).not.toBe(before.revision);
	});

	it("changes when a file is renamed — the name is the policy id under the http engine", () => {
		const before = loadPolicySource({ policyDir: policyDir({ "10-rule.cedar": PERMIT }) });
		const after = loadPolicySource({ policyDir: policyDir({ "11-rule.cedar": PERMIT }) });
		expect(after.revision).not.toBe(before.revision);
	});

	it("tells apart two sets whose concatenation is identical", () => {
		// The boundary moved by one newline: `text` cannot see it, the revision must.
		const one = loadPolicySource({ policyDir: policyDir({ "a.cedar": "X\n", "b.cedar": "Y" }) });
		const other = loadPolicySource({ policyDir: policyDir({ "a.cedar": "X", "b.cedar": "\nY" }) });
		expect(one.text).toBe(other.text);
		expect(one.revision).not.toBe(other.revision);
	});

	it("ignores what the loader ignores", () => {
		const bare = loadPolicySource({ policyDir: policyDir({ "10-permit.cedar": PERMIT }) });
		const withReadme = loadPolicySource({
			policyDir: policyDir({ "10-permit.cedar": PERMIT, "README.md": "not a policy" }),
		});
		expect(withReadme.revision).toBe(bare.revision);
	});

	it("covers inline policies and the empty set too", () => {
		const inline = loadPolicySource({ policies: PERMIT });
		expect(inline.revision).toBe(loadPolicySource({ policies: PERMIT }).revision);
		expect(inline.revision).not.toBe(loadPolicySource({ policies: FORBID }).revision);

		const empty = loadPolicySource({ policyDir: policyDir({}) });
		expect(empty.revision).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(empty.revision).toBe(loadPolicySource({ policyDir: policyDir({}) }).revision);
	});

	it("carries no path: every file has a bare name beside its resolved source", () => {
		const dir = policyDir({ "10-permit.cedar": PERMIT });
		const [file] = loadPolicySource({ policyDir: dir }).files;
		expect(file.name).toBe("10-permit.cedar");
		expect(file.source).toBe(join(dir, "10-permit.cedar"));
	});
});

describe("policyIdsOf — the ids a file's policies are known by (#199)", () => {
	const file = (name: string) => ({ name, source: `/etc/verifier/policies/${name}`, text: "" });

	it("names a file's one policy for the file, without .cedar — the id the http engine gives it", () => {
		expect(policyIdsOf(file("10-permit-eng.cedar"), 1)).toEqual(["10-permit-eng"]);
	});

	it("numbers the policies of a file that holds several from 1, in the file's order", () => {
		expect(policyIdsOf(file("20-rules.cedar"), 3)).toEqual([
			"20-rules#1",
			"20-rules#2",
			"20-rules#3",
		]);
	});

	it("names the inline set's policies after its name, `policies`", () => {
		const inline = { name: "policies", source: "policies (inline)", text: "" };
		expect(policyIdsOf(inline, 1)).toEqual(["policies"]);
		expect(policyIdsOf(inline, 2)).toEqual(["policies#1", "policies#2"]);
	});

	it("names nothing in a file that holds no policy", () => {
		expect(policyIdsOf(file("00-blank.cedar"), 0)).toEqual([]);
	});

	it("refuses a file named only .cedar that holds a policy, naming where it is", () => {
		expect(() => policyIdsOf(file(".cedar"), 1)).toThrow(CedarEngineError);
		expect(() => policyIdsOf(file(".cedar"), 2)).toThrow(
			/"\/etc\/verifier\/policies\/\.cedar" yields an empty policy id/,
		);
		expect(policyIdsOf(file(".cedar"), 0)).toEqual([]);
	});

	it.each([
		["negative", -1],
		["a fraction", 1.5],
		["NaN", Number.NaN],
	])("refuses a count that is %s", (_label, count) => {
		expect(() => policyIdsOf(file("10-permit-eng.cedar"), count)).toThrow(RangeError);
	});

	it("is not exported from the package — engines name through namePolicies", () => {
		// namePolicies is the one entry point, and refuses collisions too.
		expect("policyIdsOf" in cedar).toBe(false);
	});
});

describe("namePolicies — every policy of a set, named for its file (#199)", () => {
	const file = (name: string, text: string): PolicyFile => ({
		name,
		source: `/etc/verifier/policies/${name}`,
		text,
	});
	/** Splits on blank lines — enough for the naming under test. */
	const byBlankLine = (f: PolicyFile) => f.text.split("\n\n").filter((part) => part.length > 0);

	it("names each file's policies in the files' order and each file's order", () => {
		const named = namePolicies(
			[file("10-one.cedar", "p"), file("20-two.cedar", "a\n\nb"), file("30-none.cedar", "")],
			byBlankLine,
		);
		expect(named.map(({ id, text }) => [id, text])).toEqual([
			["10-one", "p"],
			["20-two#1", "a"],
			["20-two#2", "b"],
		]);
		expect(named[2].file.source).toBe("/etc/verifier/policies/20-two.cedar");
	});

	it("refuses two policies that would share an id, naming both files", () => {
		const colliding = [file("a.cedar", "x\n\ny"), file("a#1.cedar", "z")];
		expect(() => namePolicies(colliding, byBlankLine)).toThrow(CedarEngineError);
		expect(() => namePolicies(colliding, byBlankLine)).toThrow(
			'policy id "a#1" names a policy in /etc/verifier/policies/a.cedar and one in /etc/verifier/policies/a#1.cedar',
		);
	});

	it("lets ids that only look alike stand — a#1.cedar holding two beside a.cedar holding two", () => {
		const named = namePolicies(
			[file("a.cedar", "w\n\nx"), file("a#1.cedar", "y\n\nz")],
			byBlankLine,
		);
		expect(named.map(({ id }) => id)).toEqual(["a#1", "a#2", "a#1#1", "a#1#2"]);
	});

	it("passes on what the split throws, unchanged", () => {
		const boom = new Error("unparseable");
		expect(() =>
			namePolicies([file("a.cedar", "x")], () => {
				throw boom;
			}),
		).toThrow(boom);
	});

	it("is exported from the package, for an engine built outside it", () => {
		expect(cedar.namePolicies).toBe(namePolicies);
	});
});
