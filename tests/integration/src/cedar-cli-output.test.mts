// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * How the CLI-equivalence suite (#198) reads `cedar authorize --verbose`. The
 * parser is the suite's only interpretation of the reference evaluator, so it
 * is pinned here against the CLI's literal output — without the CLI, so that a
 * change to the parser is caught on every machine, not only where the binary
 * is installed. The samples are cedar-policy-cli 4.13.0's, verbatim, and
 * 2.5.0's where it words an answer differently — the Cedar cedar-agent 0.2.2
 * runs, which the suite's http half is held to (#284).
 */

import { describe, expect, it } from "vitest";
import { parseAuthorizeOutput, parseCliVersion } from "./conformance/cedarCli.mjs";

describe("parseAuthorizeOutput — cedar authorize --verbose, read back", () => {
	it("reads an allow and the policies that determined it", () => {
		const out = [
			"",
			"ALLOW",
			"",
			"note: this decision was due to the following policies:",
			"  10-permit-eng",
			"  20-rules#2",
			"",
		].join("\n");
		expect(parseAuthorizeOutput(out)).toEqual({
			decision: "allow",
			reason: ["10-permit-eng", "20-rules#2"],
			errors: [],
		});
	});

	it("keeps an id as the CLI printed it, spaces included — only its two-space indent is the CLI's", () => {
		const out = [
			"",
			"ALLOW",
			"",
			"note: this decision was due to the following policies:",
			"   spaced id ",
			"",
		].join("\n");
		expect(parseAuthorizeOutput(out).reason).toEqual([" spaced id "]);
	});

	it("reads a deny no policy applied to", () => {
		const out = ["", "DENY", "", "note: no policies applied to this request"].join("\n");
		expect(parseAuthorizeOutput(out)).toEqual({ decision: "deny", reason: [], errors: [] });
	});

	it("reads each evaluation error with the policy that raised it", () => {
		const out = [
			"",
			"ALLOW",
			"",
			'error while evaluating policy `10-permit-eng`: `User::"alice"` does not have the attribute `dept`',
			"",
			"note: this decision was due to the following policies:",
			"  30-permit-read",
			"",
		].join("\n");
		expect(parseAuthorizeOutput(out)).toEqual({
			decision: "allow",
			reason: ["30-permit-read"],
			errors: [
				{
					policyId: "10-permit-eng",
					message: '`User::"alice"` does not have the attribute `dept`',
				},
			],
		});
	});

	it("reads cedar-policy-cli 2.5's evaluation errors too — the Cedar cedar-agent 0.2.2 runs (#284)", () => {
		const out = [
			"",
			"ALLOW",
			"",
			'error occurred while evaluating policy `10-permit-eng`: `User::"alice"` does not have the attribute: dept',
			"",
			"note: this decision was due to the following policies:",
			"  20-permit-read",
			"",
		].join("\n");
		expect(parseAuthorizeOutput(out)).toEqual({
			decision: "allow",
			reason: ["20-permit-read"],
			errors: [
				{ policyId: "10-permit-eng", message: '`User::"alice"` does not have the attribute: dept' },
			],
		});
	});

	it("refuses output it cannot read, rather than reading it as a deny", () => {
		expect(() => parseAuthorizeOutput("")).toThrow(/no decision/);
		expect(() => parseAuthorizeOutput("\nMAYBE\n")).toThrow(/no decision/);
		expect(() =>
			parseAuthorizeOutput(["", "ALLOW", "", "something the parser has not seen"].join("\n")),
		).toThrow(/something the parser has not seen/);
	});
});

describe("parseCliVersion — cedar --version", () => {
	it("reads the CLI's version", () => {
		expect(parseCliVersion("cedar-policy-cli 4.13.0\n")).toBe("4.13.0");
	});

	it("refuses anything else", () => {
		expect(() => parseCliVersion("cedar 4\n")).toThrow(/not a cedar-policy-cli version/);
	});
});
