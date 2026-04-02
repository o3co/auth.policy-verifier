import type { CollectorContext, VerifierPayload } from "@o3co/auth.policy-verifier.core";
import { ATTR_SCOPES } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { PayloadScopeCollector } from "#/collectors/PayloadScopeCollector.mjs";

const makeContext = (scope?: string): CollectorContext => ({
	payload: { scope } satisfies VerifierPayload,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
});

describe("PayloadScopeCollector", () => {
	const collector = new PayloadScopeCollector();

	it("extracts scopes from payload", async () => {
		const attrs = await collector.collect(makeContext("read:user write:doc"));
		expect(attrs.get(ATTR_SCOPES)).toEqual(["read:user", "write:doc"]);
	});

	it("returns empty array when scope missing", async () => {
		const ctx: CollectorContext = {
			payload: {} satisfies VerifierPayload,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.get(ATTR_SCOPES)).toEqual([]);
	});
});
