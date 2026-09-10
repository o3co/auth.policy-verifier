// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	CedarEngineError,
	type CedarRequest,
	type PolicySource,
	type SyncCedarPolicySet,
} from "@o3co/auth.policy-verifier.cedar";
import { describe, expect, it } from "vitest";
import { cedarWasmEngine } from "../wasmEngine.mjs";

function inline(text: string): PolicySource {
	return { files: [{ source: "policies (inline)", text }], text, description: "inline policies" };
}

/** Loads inline text; the engine's type already says the set is synchronous. */
function load(text: string): SyncCedarPolicySet {
	return cedarWasmEngine.load(inline(text));
}

function request(overrides: Partial<CedarRequest> = {}): CedarRequest {
	const principal = { type: "User", id: "alice" };
	const resource = { type: "Document", id: "42" };
	return {
		principal,
		action: { type: "Action", id: "read" },
		resource,
		context: {},
		entities: [
			{ uid: principal, attrs: {}, parents: [] },
			{ uid: resource, attrs: {}, parents: [] },
		],
		...overrides,
	};
}

describe("cedarWasmEngine — load", () => {
	it("is the in-process engine: synchronous, named wasm", () => {
		expect(cedarWasmEngine.name).toBe("wasm");
		expect(load("").async).toBe(false);
	});

	it("names the offending file on a parse error, not the concatenation", () => {
		const source: PolicySource = {
			files: [
				{ source: "/policies/ok.cedar", text: "permit(principal, action, resource);\n" },
				{ source: "/policies/broken.cedar", text: "permit(when;\n" },
			],
			text: "permit(principal, action, resource);\n\npermit(when;\n",
			description: "/policies",
		};
		expect(() => cedarWasmEngine.load(source)).toThrow(CedarEngineError);
		expect(() => cedarWasmEngine.load(source)).toThrow(/broken\.cedar failed to parse/);
	});

	it("names inline policies the same way", () => {
		expect(() => load("permit(when;")).toThrow(/policies \(inline\) failed to parse/);
	});

	it("loads the empty policy set — migration step one", () => {
		const loaded = load("");
		expect(loaded.isAuthorized(request())).toEqual({ decision: "deny", reason: [], errors: [] });
	});
});

describe("cedarWasmEngine — isAuthorized answers Cedar's own response", () => {
	it("reports allow with the determining permit", () => {
		const loaded = load("permit(principal, action, resource);");
		const answer = loaded.isAuthorized(request());
		expect(answer.decision).toBe("allow");
		expect(answer.reason).toHaveLength(1);
		expect(answer.errors).toEqual([]);
	});

	it("reports deny with the determining forbid, even beside a permit", () => {
		const loaded = load(`
				permit(principal, action, resource);
				forbid(principal, action, resource) when { context.suspended == true };
			`);
		const answer = loaded.isAuthorized(request({ context: { suspended: true } }));
		expect(answer.decision).toBe("deny");
		expect(answer.reason).toHaveLength(1);
		expect(answer.errors).toEqual([]);
	});

	it("reports deny with no reason when no policy determined the request", () => {
		const loaded = load(`permit(principal, action, resource) when { principal.dept == "eng" };`);
		const principal = { type: "User", id: "alice" };
		const answer = loaded.isAuthorized(
			request({
				entities: [{ uid: principal, attrs: { dept: "sales" }, parents: [] }],
			}),
		);
		expect(answer).toEqual({ decision: "deny", reason: [], errors: [] });
	});

	it("reports evaluation errors naming the policy — the missing-attribute case", () => {
		const loaded = load(`permit(principal, action, resource) when { principal.dept == "eng" };`);
		const answer = loaded.isAuthorized(request());
		expect(answer.decision).toBe("deny");
		expect(answer.errors).toHaveLength(1);
		expect(answer.errors[0]).toMatch(/^policy0: /);
		expect(answer.errors[0]).toMatch(/does not have the attribute/);
	});

	it("reads inline entities: parents and entity-reference attributes", () => {
		const loaded = load(`
				permit(principal in Group::"admins", action, resource);
				permit(principal, action, resource) when { resource.owner == principal };
			`);
		const principal = { type: "User", id: "alice" };
		const resource = { type: "Document", id: "42" };
		const member = loaded.isAuthorized(
			request({
				entities: [
					{ uid: principal, attrs: {}, parents: [{ type: "Group", id: "admins" }] },
					{ uid: resource, attrs: {}, parents: [] },
				],
			}),
		);
		expect(member.decision).toBe("allow");
		const owner = loaded.isAuthorized(
			request({
				entities: [
					{ uid: principal, attrs: {}, parents: [] },
					{ uid: resource, attrs: { owner: { __entity: principal } }, parents: [] },
				],
			}),
		);
		expect(owner.decision).toBe("allow");
		expect(loaded.isAuthorized(request()).decision).toBe("deny");
	});

	it("keeps two loaded policy sets apart", () => {
		const permits = load("permit(principal, action, resource);");
		const forbids = load("forbid(principal, action, resource);");
		expect(permits.isAuthorized(request()).decision).toBe("allow");
		expect(forbids.isAuthorized(request()).decision).toBe("deny");
		expect(permits.isAuthorized(request()).decision).toBe("allow");
	});
});
