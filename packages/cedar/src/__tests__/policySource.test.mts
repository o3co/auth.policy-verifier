// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadPolicySource } from "../policySource.mjs";

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
			{ source: join(dir, "broken.cedar"), text: "permit(when;\n" },
		]);
	});

	it("wraps inline policies as one file named for the config key", () => {
		expect(loadPolicySource({ policies: "permit(principal, action, resource);" })).toEqual({
			files: [{ source: "policies (inline)", text: "permit(principal, action, resource);" }],
			text: "permit(principal, action, resource);",
			description: "inline policies",
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
