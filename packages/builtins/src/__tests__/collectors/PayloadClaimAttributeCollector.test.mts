// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * #219: the operator-declared way to turn an external IdP's claims into
 * attributes the rules can see — Clerk's org role under `o.rol`, Auth0's
 * namespaced `https://example.com/roles`, Okta's groups — without a bespoke
 * collector. Same declaration shape as `RequestContextAttributeCollector`;
 * the difference is the source, and therefore the trust.
 */
import type { CollectorContext, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
import {
	ATTR_CLIENT_ID,
	ATTR_PERMISSIONS,
	ATTR_ROLES,
	ATTR_SCOPES,
	ATTR_USER_ID,
	markUntrustedRequestContext,
	reserveAttributeKeys,
} from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { PayloadClaimAttributeCollector } from "#/collectors/PayloadClaimAttributeCollector.mjs";

const NEVER_CANCELLED = new AbortController().signal;

const makeContext = (
	subject: SubjectAttributes,
	requestContext?: Record<string, unknown>,
): CollectorContext => ({
	subject,
	resource: { raw: "document:1", resourceType: "document", resourceId: "1" },
	action: "read",
	signal: NEVER_CANCELLED,
	...(requestContext !== undefined
		? { requestContext: markUntrustedRequestContext(requestContext) }
		: {}),
});

describe("PayloadClaimAttributeCollector (#219)", () => {
	it("promotes a declared claim under the operator's own key", async () => {
		const collector = new PayloadClaimAttributeCollector({
			attributes: [{ from: "org_id", to: "tenantId" }],
		});
		const attrs = await collector.collect(makeContext({ org_id: "acme" }));
		expect(attrs.get("tenantId")).toBe("acme");
	});

	it("defaults the attribute key to the claim name", async () => {
		const collector = new PayloadClaimAttributeCollector({ attributes: [{ from: "tid" }] });
		expect((await collector.collect(makeContext({ tid: "t-1" }))).get("tid")).toBe("t-1");
	});

	it("reads a nested claim by dot path — a Clerk org role", async () => {
		const collector = new PayloadClaimAttributeCollector({
			attributes: [{ from: "o.rol", to: "orgRole" }],
		});
		const attrs = await collector.collect(makeContext({ o: { id: "org_1", rol: "admin" } }));
		expect(attrs.get("orgRole")).toBe("admin");
	});

	it("reads a claim whose name itself carries dots — an Auth0 namespaced claim", async () => {
		// `https://example.com/roles` is one claim, not a path. An exact key on
		// the bag wins over walking the dots.
		const collector = new PayloadClaimAttributeCollector({
			attributes: [{ from: "https://example.com/roles", to: "appRoles", type: "string[]" }],
		});
		const attrs = await collector.collect(
			makeContext({ "https://example.com/roles": ["editor", "viewer"] }),
		);
		expect(attrs.get("appRoles")).toEqual(["editor", "viewer"]);
	});

	it("promotes nothing a mapping did not declare", async () => {
		const collector = new PayloadClaimAttributeCollector({
			attributes: [{ from: "org_id", to: "tenantId" }],
		});
		const attrs = await collector.collect(
			makeContext({ org_id: "acme", groups: ["admin"], is_admin: true }),
		);
		expect([...attrs.keys()]).toEqual(["tenantId"]);
	});

	it("skips a claim the token omitted, and a value whose type does not match", async () => {
		const collector = new PayloadClaimAttributeCollector({
			attributes: [
				{ from: "groups", type: "string[]" },
				{ from: "level", type: "number" },
			],
		});
		const attrs = await collector.collect(makeContext({ groups: "admin", level: "3" }));
		expect(attrs.size).toBe(0);
	});

	it("reads the subject bag, never the request context", async () => {
		const collector = new PayloadClaimAttributeCollector({
			attributes: [{ from: "org_id", to: "tenantId" }],
		});
		const attrs = await collector.collect(makeContext({}, { org_id: "caller-chosen" }));
		expect(attrs.size).toBe(0);
	});

	it("does not walk the prototype chain", async () => {
		const collector = new PayloadClaimAttributeCollector({
			attributes: [{ from: "constructor" }, { from: "o.toString" }],
		});
		const attrs = await collector.collect(makeContext({ o: {} }));
		expect(attrs.size).toBe(0);
	});

	it("refuses an empty attributes list and a malformed mapping at construction", () => {
		expect(() => new PayloadClaimAttributeCollector({ attributes: [] })).toThrow(
			"PayloadClaimAttributeCollector: attributes must be a non-empty array of mappings",
		);
		expect(
			() =>
				new PayloadClaimAttributeCollector({
					attributes: [{ from: "groups", type: "list" as never }],
				}),
		).toThrow(/PayloadClaimAttributeCollector: attributes\[0\]\.type must be one of/);
		expect(() => new PayloadClaimAttributeCollector({ attributes: [{ from: "" }] })).toThrow(
			"PayloadClaimAttributeCollector: attributes[0].from must be a non-empty string",
		);
	});
});

describe("PayloadClaimAttributeCollector — core's vocabulary is a valid destination", () => {
	// The source is the signature-verified token, the same trust
	// `PayloadScopeCollector` writes `scopes` from — so unlike a request-body
	// mapping, a verified claim may land on the keys the engine decides from.
	it.each([
		[ATTR_PERMISSIONS, "permissions"],
		[ATTR_ROLES, "https://example.com/roles"],
		[ATTR_SCOPES, "scp"],
	])("promotes a verified list claim onto %s", async (key, claim) => {
		const collector = new PayloadClaimAttributeCollector({
			attributes: [{ from: claim, to: key, type: "string[]" }],
		});
		const attrs = await collector.collect(makeContext({ [claim]: ["a", "b"] }));
		expect(attrs.get(key)).toEqual(["a", "b"]);
	});

	it("promotes a verified scalar claim onto userId and clientId", async () => {
		const collector = new PayloadClaimAttributeCollector({
			attributes: [
				{ from: "user_id", to: ATTR_USER_ID },
				{ from: "client_id", to: ATTR_CLIENT_ID },
			],
		});
		const attrs = await collector.collect(makeContext({ user_id: "u-1", client_id: "c-1" }));
		expect(attrs.get(ATTR_USER_ID)).toBe("u-1");
		expect(attrs.get(ATTR_CLIENT_ID)).toBe("c-1");
	});
});

describe("PayloadClaimAttributeCollector — vocabulary another package reserved", () => {
	// Another package's keys are derived from something other than the subject
	// (cedar's `request*` come from the parsed request), so a claim landing on
	// one would still be a second writer with a different meaning. Refused, as
	// the request-context collector refuses them.
	it("refuses a mapping onto a key another package owns, and names that package", () => {
		reserveAttributeKeys({
			owner: "@example/claims-plugin",
			keys: ["pluginFact"],
			reason: "written by the plugin's own facts collector",
		});
		expect(
			() =>
				new PayloadClaimAttributeCollector({
					attributes: [{ from: "anything", to: "pluginFact" }],
				}),
		).toThrow(/pluginFact.*@example\/claims-plugin.*plugin's own facts collector/s);
	});

	it("refuses such a key reached through the `to` default", () => {
		reserveAttributeKeys({ owner: "@example/claims-defaulted", keys: ["claimDefaultedKey"] });
		expect(
			() => new PayloadClaimAttributeCollector({ attributes: [{ from: "claimDefaultedKey" }] }),
		).toThrow(/claimDefaultedKey/);
	});
});
