// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext } from "@o3co/auth.policy-verifier.core";
import { markUntrustedRequestContext } from "@o3co/auth.policy-verifier.core";
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
