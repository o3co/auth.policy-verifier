// Copyright 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { ATTR_CLIENT_IP } from "#/engine/keys.mjs";
import type { CollectorContext, VerifierPayload } from "#/engine/types.mjs";
import { RequestContextCollector } from "../RequestContextCollector.mjs";

const makeContext = (requestContext?: Record<string, unknown>): CollectorContext => ({
	payload: {} as VerifierPayload,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
	requestContext,
});

describe("RequestContextCollector", () => {
	const collector = new RequestContextCollector();

	it("extracts clientIp from requestContext.ip", async () => {
		const attrs = await collector.collect(makeContext({ ip: "203.0.113.1" }));
		expect(attrs.get(ATTR_CLIENT_IP)).toBe("203.0.113.1");
	});

	it("returns empty when requestContext is undefined", async () => {
		const attrs = await collector.collect(makeContext());
		expect(attrs.size).toBe(0);
	});

	it("returns empty when ip is not a string", async () => {
		const attrs = await collector.collect(makeContext({ ip: 12345 }));
		expect(attrs.size).toBe(0);
	});

	it("returns empty when ip is missing from requestContext", async () => {
		const attrs = await collector.collect(makeContext({ other: "value" }));
		expect(attrs.size).toBe(0);
	});
});
