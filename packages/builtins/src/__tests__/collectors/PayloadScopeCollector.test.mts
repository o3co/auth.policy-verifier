// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, VerifierPayload } from "@o3co/auth.policy-verifier.core";
import { ATTR_SCOPES } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { PayloadScopeCollector } from "#/collectors/PayloadScopeCollector.mjs";

/**
 * `CollectorContext.signal` is required (#115): a pipeline supplies one per
 * collector, so a hand-built context carries one too. These fixtures are not
 * about cancellation, so it is a signal that never aborts.
 */
const NEVER_CANCELLED = new AbortController().signal;

const makeContext = (scope?: string): CollectorContext => ({
	payload: { scope } satisfies VerifierPayload,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
	signal: NEVER_CANCELLED,
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
			signal: NEVER_CANCELLED,
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.get(ATTR_SCOPES)).toEqual([]);
	});
});
