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
	});

	it("names the offending file on a parse error", () => {
		const dir = mkdtempSync(join(tmpdir(), "cedar-policies-"));
		writeFileSync(join(dir, "ok.cedar"), "permit(principal, action, resource);\n");
		writeFileSync(join(dir, "broken.cedar"), "permit(when;\n");

		expect(() => loadPolicySource({ policyDir: dir })).toThrow(/broken\.cedar/);
	});

	it("allows a directory with zero policies — migration step one", () => {
		const dir = mkdtempSync(join(tmpdir(), "cedar-policies-"));
		expect(loadPolicySource({ policyDir: dir }).text).toBe("");
	});

	it("throws on an unreadable directory", () => {
		expect(() => loadPolicySource({ policyDir: "/nonexistent/cedar-policies" })).toThrow(
			/cannot read policyDir/,
		);
	});
});
