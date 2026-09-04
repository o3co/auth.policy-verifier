// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
	ATTR_CLIENT_ID,
	ATTR_PERMISSIONS,
	ATTR_ROLES,
	ATTR_SCOPES,
	ATTR_USER_ID,
	attributeKeyReservation,
	CORE_ATTRIBUTE_KEY_OWNER,
	RESERVED_ATTRIBUTE_KEYS,
	reserveAttributeKeys,
	suggestUnreservedAttributeKey,
} from "../keys.mjs";

describe("well-known attribute keys", () => {
	it("exposes the OAuth / OIDC / RBAC attribute key constants", () => {
		expect(ATTR_SCOPES).toBe("scopes");
		expect(ATTR_PERMISSIONS).toBe("permissions");
		expect(ATTR_ROLES).toBe("roles");
		expect(ATTR_USER_ID).toBe("userId");
		expect(ATTR_CLIENT_ID).toBe("clientId");
	});
});

describe("the attribute key registry — core's own five", () => {
	it.each([[ATTR_SCOPES], [ATTR_PERMISSIONS], [ATTR_ROLES], [ATTR_USER_ID], [ATTR_CLIENT_ID]])(
		"reserves %s to core, with a reason a refusal can quote",
		(key) => {
			expect(RESERVED_ATTRIBUTE_KEYS.has(key)).toBe(true);
			expect(attributeKeyReservation(key)).toMatchObject({
				key,
				owner: CORE_ATTRIBUTE_KEY_OWNER,
			});
			expect(attributeKeyReservation(key)?.reason).toBeTypeOf("string");
		},
	);

	it("reports nothing for a key no package has claimed", () => {
		expect(RESERVED_ATTRIBUTE_KEYS.has("tenantId")).toBe(false);
		expect(attributeKeyReservation("tenantId")).toBeUndefined();
	});
});

describe("the attribute key registry — a package reserving its own vocabulary", () => {
	it("records the owner, and the shared set sees the key live", () => {
		// Live, not a snapshot: a guard that read `RESERVED_ATTRIBUTE_KEYS` at its
		// own import time would otherwise miss every package that loads after it,
		// which is exactly the hole a frozen set left (a package's keys were
		// registered nowhere).
		expect(RESERVED_ATTRIBUTE_KEYS.has("liveViewKey")).toBe(false);

		reserveAttributeKeys({
			owner: "@example/live-view",
			keys: ["liveViewKey"],
			reason: "written by the example collector",
		});

		expect(RESERVED_ATTRIBUTE_KEYS.has("liveViewKey")).toBe(true);
		expect(attributeKeyReservation("liveViewKey")).toEqual({
			key: "liveViewKey",
			owner: "@example/live-view",
			reason: "written by the example collector",
		});
	});

	it("is idempotent for the same owner, so a re-imported module is not a failure", () => {
		const reserve = () =>
			reserveAttributeKeys({ owner: "@example/idempotent", keys: ["idempotentKey"] });

		reserve();
		expect(reserve).not.toThrow();
		expect(attributeKeyReservation("idempotentKey")?.owner).toBe("@example/idempotent");
	});

	it("refuses a key another package already owns, naming both", () => {
		reserveAttributeKeys({ owner: "@example/first", keys: ["contestedKey"] });

		expect(() =>
			reserveAttributeKeys({ owner: "@example/second", keys: ["contestedKey"] }),
		).toThrow(/contestedKey.*@example\/first.*@example\/second/s);
	});

	it("refuses a package claiming one of core's keys", () => {
		expect(() => reserveAttributeKeys({ owner: "@example/greedy", keys: [ATTR_SCOPES] })).toThrow(
			new RegExp(`${ATTR_SCOPES}.*${CORE_ATTRIBUTE_KEY_OWNER}`, "s"),
		);
	});

	it("leaves the earlier keys of a batch reserved by nobody when a later one collides", () => {
		// All-or-nothing: a half-applied reservation would leave the owning
		// package believing it holds a key the registry never recorded.
		reserveAttributeKeys({ owner: "@example/holder", keys: ["heldKey"] });

		expect(() =>
			reserveAttributeKeys({ owner: "@example/batch", keys: ["batchFirstKey", "heldKey"] }),
		).toThrow(/heldKey/);
		expect(RESERVED_ATTRIBUTE_KEYS.has("batchFirstKey")).toBe(false);
	});

	it.each([
		[{ owner: "", keys: ["k"] }, /owner/],
		[{ owner: 7, keys: ["k"] }, /owner/],
		[{ owner: "@example/bad", keys: [""] }, /key/],
		[{ owner: "@example/bad", keys: [3] }, /key/],
	])("rejects the malformed reservation %j", (reservation, pattern) => {
		expect(() =>
			reserveAttributeKeys(reservation as unknown as Parameters<typeof reserveAttributeKeys>[0]),
		).toThrow(pattern);
	});
});

describe("suggestUnreservedAttributeKey", () => {
	it("promotes a core key under the request namespace", () => {
		expect(suggestUnreservedAttributeKey(ATTR_SCOPES)).toBe("requestScopes");
	});

	it("never proposes a name that is itself reserved", () => {
		reserveAttributeKeys({ owner: "@example/occupier", keys: ["requestOccupied"] });

		const suggestion = suggestUnreservedAttributeKey("occupied");

		expect(suggestion).not.toBe("requestOccupied");
		expect(RESERVED_ATTRIBUTE_KEYS.has(suggestion)).toBe(false);
	});

	it("does not stutter for a key that already lives in the request namespace", () => {
		// The remedy the refusal advises must not walk into the vocabulary that
		// produced the refusal: `packages/cedar` owns `request*`.
		reserveAttributeKeys({ owner: "@example/cedar-like", keys: ["requestResourceIdLike"] });

		const suggestion = suggestUnreservedAttributeKey("requestResourceIdLike");

		expect(suggestion).not.toMatch(/^requestRequest/);
		expect(RESERVED_ATTRIBUTE_KEYS.has(suggestion)).toBe(false);
	});

	it("falls back past every prefix when they are all taken", () => {
		reserveAttributeKeys({
			owner: "@example/exhaustive",
			keys: ["crowded", "requestCrowded", "callerCrowded", "contextCrowded", "crowdedAttribute"],
		});

		expect(suggestUnreservedAttributeKey("crowded")).toBe("crowdedAttribute2");
	});
});
