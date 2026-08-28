// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { CollectorContext } from "../types.mjs";
import type { UntrustedRequestContext } from "../untrusted.mjs";
import { markUntrustedRequestContext, readUntrustedRequestContext } from "../untrusted.mjs";

describe("UntrustedRequestContext", () => {
	it("hands back the record the transport marked", () => {
		const raw = { subscriber_did: "did:example:alice" };

		expect(readUntrustedRequestContext(markUntrustedRequestContext(raw))).toBe(raw);
	});

	it("reads an absent request context as absent", () => {
		// `CollectorContext.requestContext` is optional, so every collector meets
		// `undefined` on the first request that carries no body context.
		expect(readUntrustedRequestContext(undefined)).toBeUndefined();
	});

	it("does not expose a marked field as a property", () => {
		const marked = markUntrustedRequestContext({ role: "admin" });

		// @ts-expect-error — reading a field straight off the brand must not
		// compile. A collector has to name the value untrusted before it can read
		// it, which is the acknowledgement this type exists to force.
		const smuggled: unknown = marked.role;
		expect(smuggled).toBeUndefined();
	});

	it("refuses a bare record where a marked context is required", () => {
		// @ts-expect-error — only `markUntrustedRequestContext` mints the brand, so
		// a transport cannot hand collectors a raw body object by accident.
		const forged: UntrustedRequestContext = { role: "admin" };
		expect(readUntrustedRequestContext(forged)).toBeUndefined();
	});

	it("keeps caller-supplied fields off the object's own enumerable keys", () => {
		// The payload hangs off a symbol key, so a serializer that walks the
		// collector context — an audit log, a debug dump — cannot copy caller data
		// out of it without going through the accessor.
		const marked = markUntrustedRequestContext({ role: "admin", tenant: "acme" });

		expect(Object.keys(marked)).toEqual([]);
		expect(JSON.stringify(marked)).toBe("{}");
	});

	it("types CollectorContext.requestContext as the marked form", () => {
		const context: CollectorContext = {
			subject: {},
			resource: { raw: "project:1", resourceType: "project", resourceId: "1" },
			action: "read",
			requestContext: markUntrustedRequestContext({ tenant: "acme" }),
			signal: new AbortController().signal,
		};

		expect(readUntrustedRequestContext(context.requestContext)).toEqual({ tenant: "acme" });
	});
});
