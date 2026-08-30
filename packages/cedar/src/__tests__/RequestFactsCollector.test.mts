// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import {
	ATTR_REQUEST_ACTION,
	ATTR_REQUEST_RESOURCE_ID,
	ATTR_REQUEST_RESOURCE_RAW,
	ATTR_REQUEST_RESOURCE_TYPE,
} from "../keys.mjs";
import { RequestFactsCollector } from "../RequestFactsCollector.mjs";

function contextFor(resource: CollectorContext["resource"]): CollectorContext {
	return {
		subject: { sub: "user-1" },
		resource,
		action: "read",
		signal: new AbortController().signal,
	};
}

describe("RequestFactsCollector", () => {
	it("promotes action and the parsed resource into attributes", async () => {
		const attrs = await new RequestFactsCollector().collect(
			contextFor({ raw: "document:42", resourceType: "document", resourceId: "42" }),
		);
		expect(attrs.get(ATTR_REQUEST_ACTION)).toBe("read");
		expect(attrs.get(ATTR_REQUEST_RESOURCE_TYPE)).toBe("document");
		expect(attrs.get(ATTR_REQUEST_RESOURCE_ID)).toBe("42");
		expect(attrs.get(ATTR_REQUEST_RESOURCE_RAW)).toBe("document:42");
	});

	it("leaves requestResourceId absent when the parser produced none", async () => {
		const attrs = await new RequestFactsCollector().collect(
			contextFor({ raw: "document", resourceType: "document" }),
		);
		expect(attrs.has(ATTR_REQUEST_RESOURCE_ID)).toBe(false);
	});
});
