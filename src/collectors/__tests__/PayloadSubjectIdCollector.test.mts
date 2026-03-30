import { describe, it, expect } from "vitest";
import { PayloadSubjectIdCollector } from "../PayloadSubjectIdCollector.mjs";
import { ATTR_USER_ID, ATTR_CLIENT_ID } from "#/engine/keys.mjs";
import type { CollectorContext } from "#/engine/types.mjs";

describe("PayloadSubjectIdCollector", () => {
	const collector = new PayloadSubjectIdCollector();

	it("extracts userId from payload.user.id", async () => {
		const ctx: CollectorContext = {
			payload: { user: { id: "u1" }, scopes: [] } as any,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.get(ATTR_USER_ID)).toBe("u1");
	});

	it("extracts clientId from payload.client.id", async () => {
		const ctx: CollectorContext = {
			payload: { client: { id: "c1" }, scopes: [] } as any,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.get(ATTR_CLIENT_ID)).toBe("c1");
	});

	it("returns empty map when neither user nor client present", async () => {
		const ctx: CollectorContext = {
			payload: { scopes: [] } as any,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.size).toBe(0);
	});
});
