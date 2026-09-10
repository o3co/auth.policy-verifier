// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
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
	subject: { scope } satisfies SubjectAttributes,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
	signal: NEVER_CANCELLED,
});

describe("PayloadScopeCollector", () => {
	const collector = new PayloadScopeCollector();

	it("extracts scopes from subject", async () => {
		const attrs = await collector.collect(makeContext("read:user write:doc"));
		expect(attrs.get(ATTR_SCOPES)).toEqual(["read:user", "write:doc"]);
	});

	it("returns empty array when scope missing", async () => {
		const ctx: CollectorContext = {
			subject: {} satisfies SubjectAttributes,
			resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
			action: "read",
			signal: NEVER_CANCELLED,
		};
		const attrs = await collector.collect(ctx);
		expect(attrs.get(ATTR_SCOPES)).toEqual([]);
	});
});

describe("PayloadScopeCollector — the claim option (#219)", () => {
	const ctx = (subject: SubjectAttributes): CollectorContext => ({
		subject,
		resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
		action: "read",
		signal: NEVER_CANCELLED,
	});

	it("reads an array-valued claim, the way Okta emits scp", async () => {
		const collector = new PayloadScopeCollector({ claim: "scp" });
		const attrs = await collector.collect(ctx({ scp: ["openid", "read:project"] }));
		expect(attrs.get(ATTR_SCOPES)).toEqual(["openid", "read:project"]);
	});

	it("reads a space-delimited string under another claim name", async () => {
		const collector = new PayloadScopeCollector({ claim: "permissions" });
		const attrs = await collector.collect(ctx({ permissions: "read:project write:project" }));
		expect(attrs.get(ATTR_SCOPES)).toEqual(["read:project", "write:project"]);
	});

	it("still reads scope by default, and accepts it as an array too", async () => {
		const collector = new PayloadScopeCollector();
		expect((await collector.collect(ctx({ scope: ["a", "b"] }))).get(ATTR_SCOPES)).toEqual([
			"a",
			"b",
		]);
		expect((await collector.collect(ctx({ scp: ["a"] }))).get(ATTR_SCOPES)).toEqual([]);
	});

	it("drops empty entries, and treats a list carrying a non-string as no scopes at all", async () => {
		const collector = new PayloadScopeCollector({ claim: "scp" });
		expect((await collector.collect(ctx({ scp: ["a", "", "b"] }))).get(ATTR_SCOPES)).toEqual([
			"a",
			"b",
		]);
		// A list that is not a list of scopes asserts no capability, the way a
		// non-string `scope` never did — fail closed rather than pick the strings out.
		expect((await collector.collect(ctx({ scp: ["a", 7] }))).get(ATTR_SCOPES)).toEqual([]);
	});

	it("refuses an empty or non-string claim at construction", () => {
		for (const claim of ["", 42, null]) {
			expect(() => new PayloadScopeCollector({ claim } as never)).toThrow(
				"PayloadScopeCollector: claim must be a non-empty string",
			);
		}
	});
});
