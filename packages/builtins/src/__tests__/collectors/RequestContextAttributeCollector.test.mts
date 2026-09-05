// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext } from "@o3co/auth.policy-verifier.core";
import {
	ATTR_CLIENT_ID,
	ATTR_PERMISSIONS,
	ATTR_ROLES,
	ATTR_SCOPES,
	ATTR_USER_ID,
	markUntrustedRequestContext,
	RESERVED_ATTRIBUTE_KEYS,
	reserveAttributeKeys,
} from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { RequestContextAttributeCollector } from "#/collectors/RequestContextAttributeCollector.mjs";

/**
 * `CollectorContext.signal` is required (#115): a pipeline supplies one per
 * collector, so a hand-built context carries one too. These fixtures are not
 * about cancellation, so it is a signal that never aborts.
 */
const NEVER_CANCELLED = new AbortController().signal;

const makeContext = (requestContext?: Record<string, unknown>): CollectorContext => ({
	subject: {},
	resource: { raw: "document:1", resourceType: "document", resourceId: "1" },
	action: "read",
	signal: NEVER_CANCELLED,
	...(requestContext !== undefined
		? { requestContext: markUntrustedRequestContext(requestContext) }
		: {}),
});

describe("RequestContextAttributeCollector", () => {
	it("promotes a declared field under the operator's own key", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "tenant_id", to: "tenantId" }],
		});

		const attrs = await collector.collect(makeContext({ tenant_id: "acme" }));

		expect(attrs.get("tenantId")).toBe("acme");
	});

	it("defaults the attribute key to the source field name", async () => {
		const collector = new RequestContextAttributeCollector({ attributes: [{ from: "region" }] });

		const attrs = await collector.collect(makeContext({ region: "eu-west-1" }));

		expect(attrs.get("region")).toBe("eu-west-1");
	});

	it("reads a nested field by dot path", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "tenant.id", to: "tenantId" }],
		});

		const attrs = await collector.collect(makeContext({ tenant: { id: "acme" } }));

		expect(attrs.get("tenantId")).toBe("acme");
	});

	it("promotes nothing a mapping did not declare", async () => {
		// requestContext is free-form caller-supplied data; only declared fields
		// become attributes, so a rule cannot be steered by an unexpected key.
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "tenant_id", to: "tenantId" }],
		});

		const attrs = await collector.collect(
			makeContext({ tenant_id: "acme", roles: ["admin"], is_admin: true }),
		);

		expect([...attrs.keys()]).toEqual(["tenantId"]);
	});

	it("skips a field the request omitted", async () => {
		const collector = new RequestContextAttributeCollector({ attributes: [{ from: "tenant_id" }] });

		const attrs = await collector.collect(makeContext({}));

		expect(attrs.size).toBe(0);
	});

	it("returns nothing when the request carries no context at all", async () => {
		const collector = new RequestContextAttributeCollector({ attributes: [{ from: "tenant_id" }] });

		const attrs = await collector.collect(makeContext());

		expect(attrs.size).toBe(0);
	});

	it("skips an empty string", async () => {
		const collector = new RequestContextAttributeCollector({ attributes: [{ from: "tenant_id" }] });

		const attrs = await collector.collect(makeContext({ tenant_id: "" }));

		expect(attrs.size).toBe(0);
	});

	it("skips a value whose type does not match the declaration", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "tenant_id", type: "string" }],
		});

		const attrs = await collector.collect(makeContext({ tenant_id: 42 }));

		expect(attrs.size).toBe(0);
	});

	it.each([
		["number", 42, 42],
		["boolean", true, true],
	])("promotes a declared %s", async (type, value, expected) => {
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "v", type: type as "number" | "boolean" }],
		});

		const attrs = await collector.collect(makeContext({ v: value }));

		expect(attrs.get("v")).toBe(expected);
	});

	it("promotes a declared string list", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "groups", type: "string[]" }],
		});

		const attrs = await collector.collect(makeContext({ groups: ["eng", "sre"] }));

		expect(attrs.get("groups")).toEqual(["eng", "sre"]);
	});

	it("skips a list carrying a non-string element", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "groups", type: "string[]" }],
		});

		const attrs = await collector.collect(makeContext({ groups: ["eng", 7] }));

		expect(attrs.size).toBe(0);
	});

	it("skips NaN for a declared number", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "v", type: "number" }],
		});

		const attrs = await collector.collect(makeContext({ v: Number.NaN }));

		expect(attrs.size).toBe(0);
	});

	it("does not walk the prototype chain", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [
				{ from: "constructor.name", to: "x" },
				{ from: "toString", to: "y" },
			],
		});

		const attrs = await collector.collect(makeContext({}));

		expect(attrs.size).toBe(0);
	});

	it.each([
		[{ attributes: [] }, /attributes/],
		[{ attributes: [{ from: "" }] }, /from/],
		[{ attributes: [{ to: "x" }] }, /from/],
		[{ attributes: [{ from: "a", type: "object" }] }, /type/],
		[{ attributes: [{ from: "a", to: 1 }] }, /to/],
	])("rejects %j at construction time", (config, pattern) => {
		expect(
			() =>
				new RequestContextAttributeCollector(
					config as unknown as ConstructorParameters<typeof RequestContextAttributeCollector>[0],
				),
		).toThrow(pattern);
	});
});

describe("RequestContextAttributeCollector — the reserved core vocabulary", () => {
	// The guard exists because of what happens *downstream*: `AttributePipeline`
	// unions array-valued attributes across collectors, so a mapping onto
	// `scopes` does not overwrite the token-derived list, it extends it. The
	// request body would top up the signed token, silently.
	it.each([[ATTR_SCOPES], [ATTR_PERMISSIONS], [ATTR_ROLES], [ATTR_USER_ID], [ATTR_CLIENT_ID]])(
		"refuses a mapping whose `to` is the reserved key %s",
		(key) => {
			expect(
				() => new RequestContextAttributeCollector({ attributes: [{ from: "anything", to: key }] }),
			).toThrow(new RegExp(`reserved core attribute "${key}"`));
		},
	);

	it("refuses a reserved key reached through the `to` default", () => {
		// `to` defaults to `from`, so `{ from: "scopes" }` writes `scopes` just
		// as surely as spelling it out would.
		expect(
			() => new RequestContextAttributeCollector({ attributes: [{ from: ATTR_SCOPES }] }),
		).toThrow(/reserved core attribute "scopes"/);
	});

	it("names the offending mapping's index and says why", () => {
		expect(
			() =>
				new RequestContextAttributeCollector({
					attributes: [
						{ from: "tenant_id", to: "tenantId" },
						{ from: "groups", to: ATTR_ROLES },
					],
				}),
		).toThrow(/attributes\[1\].*caller-supplied/s);
	});

	it("still promotes a reserved-sounding field under a key of the operator's own", () => {
		// The field name is the caller's; only the attribute key is reserved.
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: ATTR_SCOPES, to: "requestedScopes", type: "string[]" }],
		});

		expect(collector).toBeInstanceOf(RequestContextAttributeCollector);
	});

	it("leaves every unreserved mapping working", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [
				{ from: "tenant.id", to: "tenantId" },
				{ from: "groups", type: "string[]" },
			],
		});

		const attrs = await collector.collect(
			makeContext({ tenant: { id: "acme" }, groups: ["eng", "sre"] }),
		);

		expect(attrs.get("tenantId")).toBe("acme");
		expect(attrs.get("groups")).toEqual(["eng", "sre"]);
	});
});

/**
 * The name in a refusal's "for example …" clause. Read back out of the message
 * rather than recomputed, so the test checks the advice an operator is actually
 * given.
 */
function suggestedKeyIn(message: string): string {
	const match = /for example "([^"]+)"/.exec(message);
	expect(match).not.toBeNull();
	return (match as RegExpExecArray)[1];
}

function refusalFor(to: string): string {
	try {
		new RequestContextAttributeCollector({ attributes: [{ from: "anything", to }] });
	} catch (error) {
		return (error as Error).message;
	}
	throw new Error(`expected a mapping onto "${to}" to be refused`);
}

describe("RequestContextAttributeCollector — vocabulary another package reserved", () => {
	// The reservation is a registry core exposes, not a list core enumerates:
	// `packages/cedar` owns four `request*` keys core cannot see, and any
	// consuming package may own more. Reserving one here is exactly what such a
	// package does at module load.
	it("refuses a mapping onto a key another package owns, and names that package", () => {
		reserveAttributeKeys({
			owner: "@example/policy-plugin",
			keys: ["pluginResourceId"],
			reason: "written by the plugin's own request-facts collector",
		});

		const message = refusalFor("pluginResourceId");

		expect(message).toContain("attributes[0]");
		expect(message).toContain('"pluginResourceId"');
		expect(message).toContain("@example/policy-plugin");
		expect(message).toContain("written by the plugin's own request-facts collector");
	});

	it("does not call another package's key core's own", () => {
		reserveAttributeKeys({ owner: "@example/other", keys: ["otherOwnedKey"] });

		expect(refusalFor("otherOwnedKey")).not.toContain("reserved core attribute");
	});

	it("refuses such a key reached through the `to` default", () => {
		reserveAttributeKeys({ owner: "@example/defaulted", keys: ["defaultedKey"] });

		expect(
			() => new RequestContextAttributeCollector({ attributes: [{ from: "defaultedKey" }] }),
		).toThrow(/defaultedKey/);
	});

	it("suggests a rename that is not itself reserved", () => {
		// The advice used to be "call it request<Key>" unconditionally — into the
		// namespace `packages/cedar` occupies, so it could propose a name the very
		// next guard refuses.
		reserveAttributeKeys({
			owner: "@example/crowding",
			keys: ["crowdedKey", "requestCrowdedKey"],
		});

		const suggestion = suggestedKeyIn(refusalFor("crowdedKey"));

		expect(suggestion).not.toBe("requestCrowdedKey");
		expect(RESERVED_ATTRIBUTE_KEYS.has(suggestion)).toBe(false);
		// And the suggestion is usable: it constructs.
		expect(
			new RequestContextAttributeCollector({
				attributes: [{ from: "crowdedKey", to: suggestion }],
			}),
		).toBeInstanceOf(RequestContextAttributeCollector);
	});

	it("still advises the request namespace for a core key, which is free", () => {
		expect(suggestedKeyIn(refusalFor(ATTR_SCOPES))).toBe("requestScopes");
	});

	it("leaves a key nobody reserved working", async () => {
		const collector = new RequestContextAttributeCollector({
			attributes: [{ from: "rid", to: "callerSuppliedResourceId" }],
		});

		const attrs = await collector.collect(makeContext({ rid: "someone-elses-doc" }));

		expect(attrs.get("callerSuppliedResourceId")).toBe("someone-elses-doc");
	});
});
