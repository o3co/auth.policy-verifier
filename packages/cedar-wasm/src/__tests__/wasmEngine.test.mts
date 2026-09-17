// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	CedarEngineError,
	type CedarRequest,
	computePolicyRevision,
	type PolicySource,
	type SyncCedarPolicySet,
} from "@o3co/auth.policy-verifier.cedar";
import { describe, expect, it } from "vitest";
import { cedarWasmEngine } from "../wasmEngine.mjs";

function inline(text: string): PolicySource {
	const files = [{ name: "policies", source: "policies (inline)", text }];
	return { files, text, description: "inline policies", revision: computePolicyRevision(files) };
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
		const files = [
			{
				name: "ok.cedar",
				source: "/policies/ok.cedar",
				text: "permit(principal, action, resource);\n",
			},
			{ name: "broken.cedar", source: "/policies/broken.cedar", text: "permit(when;\n" },
		];
		const source: PolicySource = {
			files,
			text: "permit(principal, action, resource);\n\npermit(when;\n",
			description: "/policies",
			revision: computePolicyRevision(files),
		};
		expect(() => cedarWasmEngine.load(source)).toThrow(CedarEngineError);
		expect(() => cedarWasmEngine.load(source)).toThrow(/broken\.cedar failed to parse/);
	});

	it("names inline policies the same way", () => {
		expect(() => load("permit(when;")).toThrow(/policies \(inline\) failed to parse/);
	});

	it("loads the empty policy set — migration step one", () => {
		const loaded = load("");
		expect(loaded.isAuthorized(request())).toEqual({
			decision: "deny",
			reason: [],
			errors: [],
			revision: inline("").revision,
		});
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
		expect(answer).toMatchObject({ decision: "deny", reason: [], errors: [] });
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

/*
 * #244: the confirmation contract, from the engine that can honour it. The set
 * is compiled in this process, under an id nothing else holds, from the source
 * `load` was handed — so an answer can only have come from that source, and
 * the engine says so on every one of them.
 */
describe("cedarWasmEngine — vouches for the revision it evaluated", () => {
	it("declares it, so requireConfirmedRevision boots over this engine", () => {
		expect(cedarWasmEngine.confirmsRevision).toBe(true);
	});

	it("names the loaded source's revision on an allow, a deny and an erroring answer alike", () => {
		const permit = inline("permit(principal, action, resource);");
		expect(cedarWasmEngine.load(permit).isAuthorized(request())).toMatchObject({
			decision: "allow",
			revision: permit.revision,
		});

		const forbid = inline("forbid(principal, action, resource);");
		expect(cedarWasmEngine.load(forbid).isAuthorized(request())).toMatchObject({
			decision: "deny",
			revision: forbid.revision,
		});

		const erroring = inline(
			`permit(principal, action, resource) when { principal.dept == "eng" };`,
		);
		const answer = cedarWasmEngine.load(erroring).isAuthorized(request());
		expect(answer.errors).toHaveLength(1);
		expect(answer.revision).toBe(erroring.revision);
	});

	it("vouches for what it loaded, not for what the source says later", () => {
		// The claim is about the set that was COMPILED. A `PolicySource` is a
		// plain object the caller still holds; rewriting it after `load` changes
		// nothing about the compiled policies, so it must change nothing about
		// the revision an answer names (#244: capture it with the snapshot, do
		// not read "the current revision" when answering).
		const source = inline("permit(principal, action, resource);");
		const loadedRevision = source.revision;
		const loaded = cedarWasmEngine.load(source);
		(source as { revision: string }).revision = inline(
			"forbid(principal, action, resource);",
		).revision;

		const answer = loaded.isAuthorized(request());
		expect(answer.decision).toBe("allow");
		expect(answer.revision).toBe(loadedRevision);
	});

	it("keeps concurrently loaded sets apart — each answers with its own revision", () => {
		const one = inline("permit(principal, action, resource);");
		const other = inline("forbid(principal, action, resource);");
		const loadedOne = cedarWasmEngine.load(one);
		const loadedOther = cedarWasmEngine.load(other);
		expect(loadedOther.isAuthorized(request()).revision).toBe(other.revision);
		expect(loadedOne.isAuthorized(request()).revision).toBe(one.revision);
	});
});
