import { describe, expect, it } from "vitest";
import { ATTR_SCOPES } from "#/engine/keys.mjs";
import type { CollectorContext, VerifierPayload } from "#/engine/types.mjs";
import { PayloadScopeCollector } from "../PayloadScopeCollector.mjs";

const makeContext = (scopes: string[]): CollectorContext => ({
	payload: { scopes } satisfies VerifierPayload,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
});

describe("PayloadScopeCollector", () => {
	const collector = new PayloadScopeCollector();

	it("extracts scopes from payload", async () => {
		const attrs = await collector.collect(makeContext(["read:user", "write:doc"]));
		expect(attrs.get(ATTR_SCOPES)).toEqual(["read:user", "write:doc"]);
	});

	it("returns empty array when scopes missing", async () => {
		const ctx: CollectorContext = {
			payload: {} satisfies VerifierPayload,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.get(ATTR_SCOPES)).toEqual([]);
	});
});
