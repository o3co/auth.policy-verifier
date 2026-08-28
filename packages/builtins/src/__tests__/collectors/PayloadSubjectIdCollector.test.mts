// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
import { ATTR_CLIENT_ID, ATTR_USER_ID } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { PayloadSubjectIdCollector } from "#/collectors/PayloadSubjectIdCollector.mjs";

/**
 * `CollectorContext.signal` is required (#115): a pipeline supplies one per
 * collector, so a hand-built context carries one too. These fixtures are not
 * about cancellation, so it is a signal that never aborts.
 */
const NEVER_CANCELLED = new AbortController().signal;

const makeContext = (subject: SubjectAttributes): CollectorContext => ({
	subject,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
	signal: NEVER_CANCELLED,
});

describe("PayloadSubjectIdCollector", () => {
	const collector = new PayloadSubjectIdCollector();

	it("extracts userId from subject.sub", async () => {
		const attrs = await collector.collect(makeContext({ sub: "u1" }));
		expect(attrs.get(ATTR_USER_ID)).toBe("u1");
	});

	it("extracts clientId from subject.azp", async () => {
		const attrs = await collector.collect(makeContext({ azp: "c1" }));
		expect(attrs.get(ATTR_CLIENT_ID)).toBe("c1");
	});

	it("returns empty map when neither sub nor azp present", async () => {
		const attrs = await collector.collect(makeContext({}));
		expect(attrs.size).toBe(0);
	});

	it("promotes neither claim when its value is not a string", async () => {
		// `SubjectAttributes` is a bag of unknowns (#170): the claim vocabulary
		// and its narrowing are this collector's, so a `sub` that is not a string
		// must not become an identity attribute.
		const attrs = await collector.collect(makeContext({ sub: 42, azp: ["c1"] }));
		expect(attrs.size).toBe(0);
	});

	it("promotes neither claim when its value is an empty string", async () => {
		const attrs = await collector.collect(makeContext({ sub: "", azp: "" }));
		expect(attrs.size).toBe(0);
	});
});
