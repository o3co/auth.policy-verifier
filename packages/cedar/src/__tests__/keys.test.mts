// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Nothing of this package is imported statically here, and that is the point:
 * the first test asserts what the registry looks like *before* the package
 * loads, so the ordering property the design rests on — the keys are reserved
 * by loading the package, not by initializing its `Module` or constructing its
 * collectors — is actually observed rather than assumed.
 */

import { describe, expect, it } from "vitest";

const CEDAR_KEYS = [
	"requestAction",
	"requestResourceType",
	"requestResourceId",
	"requestResourceRaw",
] as const;

describe("the cedar vocabulary is reserved by loading the package", () => {
	it("registers every key into core's registry on import, and not before", async () => {
		// Core is loaded first, and by package specifier — the same instance
		// `packages/cedar` and `packages/builtins` resolve. A reservation that
		// landed in some other copy of core would not be visible here.
		const core = await import("@o3co/auth.policy-verifier.core");
		for (const key of CEDAR_KEYS) {
			expect(core.RESERVED_ATTRIBUTE_KEYS.has(key)).toBe(false);
		}

		// Importing the package entry point is all a composition does before it
		// can name `RequestFactsCollector` or `CedarPolicyRuleCollector` in
		// config; no `init` is run and no collector is constructed here.
		const cedar = await import("../index.mjs");

		for (const key of CEDAR_KEYS) {
			expect(core.RESERVED_ATTRIBUTE_KEYS.has(key)).toBe(true);
			expect(core.attributeKeyReservation(key)).toMatchObject({
				key,
				owner: cedar.CEDAR_ATTRIBUTE_KEY_OWNER,
			});
			expect(core.attributeKeyReservation(key)?.reason).toBeTypeOf("string");
		}
	});

	it("owns exactly the keys its collector writes", async () => {
		const cedar = await import("../index.mjs");

		expect(cedar.CEDAR_ATTRIBUTE_KEY_OWNER).toBe("@o3co/auth.policy-verifier.cedar");
		expect([...cedar.CEDAR_ATTRIBUTE_KEYS]).toEqual([
			cedar.ATTR_REQUEST_ACTION,
			cedar.ATTR_REQUEST_RESOURCE_TYPE,
			cedar.ATTR_REQUEST_RESOURCE_ID,
			cedar.ATTR_REQUEST_RESOURCE_RAW,
		]);
		expect([...cedar.CEDAR_ATTRIBUTE_KEYS]).toEqual([...CEDAR_KEYS]);
	});

	it("tolerates a second copy of the package reserving the same keys", async () => {
		// Two versions of this package on one dependency graph both run their
		// module body. Same owner, same keys: a no-op, not a boot failure.
		const core = await import("@o3co/auth.policy-verifier.core");
		const cedar = await import("../index.mjs");

		expect(() =>
			core.reserveAttributeKeys({
				owner: cedar.CEDAR_ATTRIBUTE_KEY_OWNER,
				keys: cedar.CEDAR_ATTRIBUTE_KEYS,
			}),
		).not.toThrow();
	});

	it("keeps the id-less-resource key reserved even though the collector may not write it", async () => {
		// `RequestFactsCollector` writes `requestResourceId` only when the parsed
		// resource carried one, so for a resource like "document" there is no
		// competing writer and nothing would collide with a caller-supplied
		// value. The reservation, not the collision, is what closes that.
		const core = await import("@o3co/auth.policy-verifier.core");
		const { ATTR_REQUEST_RESOURCE_ID, RequestFactsCollector } = await import("../index.mjs");

		const attrs = await new RequestFactsCollector().collect({
			subject: { sub: "user-1" },
			resource: { raw: "document", resourceType: "document" },
			action: "read",
			signal: new AbortController().signal,
		});

		expect(attrs.has(ATTR_REQUEST_RESOURCE_ID)).toBe(false);
		expect(core.RESERVED_ATTRIBUTE_KEYS.has(ATTR_REQUEST_RESOURCE_ID)).toBe(true);
	});
});
