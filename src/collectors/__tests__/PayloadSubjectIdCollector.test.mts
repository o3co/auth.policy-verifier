import { describe, expect, it } from "vitest";
import { ATTR_CLIENT_ID, ATTR_USER_ID } from "#/engine/keys.mjs";
import type { CollectorContext, VerifierPayload } from "#/engine/types.mjs";
import { PayloadSubjectIdCollector } from "../PayloadSubjectIdCollector.mjs";

describe("PayloadSubjectIdCollector", () => {
	const collector = new PayloadSubjectIdCollector();

	it("extracts userId from payload.sub", async () => {
		const ctx: CollectorContext = {
			payload: { sub: "u1" } satisfies VerifierPayload,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.get(ATTR_USER_ID)).toBe("u1");
	});

	it("extracts clientId from payload.azp", async () => {
		const ctx: CollectorContext = {
			payload: { azp: "c1" } satisfies VerifierPayload,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.get(ATTR_CLIENT_ID)).toBe("c1");
	});

	it("returns empty map when neither sub nor azp present", async () => {
		const ctx: CollectorContext = {
			payload: {} satisfies VerifierPayload,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.size).toBe(0);
	});
});
