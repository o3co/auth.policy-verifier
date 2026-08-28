// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { AttributePipeline } from "../AttributePipeline.mjs";
import { AttributeConflictError } from "../errors.mjs";
import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
	CollectorRequest,
	SubjectAttributes,
} from "../types.mjs";

// A `CollectorRequest`, not a `CollectorContext`: the per-collector `signal` is
// the pipeline's to supply, and this is the shape a transport hands it (#115).
const stubContext: CollectorRequest = {
	subject: {} satisfies SubjectAttributes,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
};

const makeCollector = (result: Attributes): AttributeCollector => ({
	collect: async (_ctx: CollectorContext) => result,
});

describe("AttributePipeline", () => {
	it("returns empty map when no collectors", async () => {
		const pipeline = new AttributePipeline([]);
		const result = await pipeline.collect(stubContext);
		expect(result.size).toBe(0);
	});

	it("returns attributes from a single collector", async () => {
		const attrs: Attributes = new Map([["scopes", ["read:user"]]]);
		const pipeline = new AttributePipeline([makeCollector(attrs)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("scopes")).toEqual(["read:user"]);
	});

	it("concatenates arrays from multiple collectors", async () => {
		const a: Attributes = new Map([["scopes", ["read:user"]]]);
		const b: Attributes = new Map([["scopes", ["write:user"]]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("scopes")).toEqual(["read:user", "write:user"]);
	});

	// #174: two collectors disagreeing on a scalar key is an integration bug,
	// and last-writer-wins let it weaken decisions silently (#126 item 2). The
	// merge now refuses the map; the transport answers the refusal as a deny.
	it("rejects two collectors writing DIFFERENT values to the same scalar key", async () => {
		const a: Attributes = new Map([["userId", "1"]]);
		const b: Attributes = new Map([["userId", "2"]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		await expect(pipeline.collect(stubContext)).rejects.toThrow(AttributeConflictError);
	});

	it("names the conflicting KEY in the error, never the values", async () => {
		const a: Attributes = new Map([["department", "sales-secret"]]);
		const b: Attributes = new Map([["department", "eng-secret"]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		const error = await pipeline.collect(stubContext).then(
			() => {
				throw new Error("unreachable: collect resolved");
			},
			(e: unknown) => e as Error,
		);
		expect(error.message).toContain("department");
		// Attribute values are claims and may be sensitive; the message travels
		// into logs, so neither value may appear.
		expect(error.message).not.toContain("sales-secret");
		expect(error.message).not.toContain("eng-secret");
	});

	it("allows an identical scalar re-write — same value is not a disagreement", async () => {
		const a: Attributes = new Map([["userId", "1"]]);
		const b: Attributes = new Map([["userId", "1"]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("userId")).toBe("1");
	});

	it("still rejects a scalar disagreement even with an array write between them", async () => {
		const a: Attributes = new Map([["userId", "1"]]);
		const b: Attributes = new Map([["userId", ["array-interlude"]]]);
		const c: Attributes = new Map([["userId", "2"]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b), makeCollector(c)]);
		await expect(pipeline.collect(stubContext)).rejects.toThrow(AttributeConflictError);
	});

	// #126 item 3 pinned the merge to one concatenation per key; these two pin
	// the mixed-type semantics the old per-map shape had, so the rewrite could
	// not drift them: a scalar overwrite RESETS accumulation (a later array
	// starts fresh), and an array replaces an earlier scalar outright.
	it("a scalar write resets array accumulation for that key", async () => {
		const a: Attributes = new Map([["scopes", ["read:user"]]]);
		const b: Attributes = new Map([["scopes", "corrupted"]]);
		const c: Attributes = new Map([["scopes", ["write:user"]]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b), makeCollector(c)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("scopes")).toEqual(["write:user"]);
	});

	it("a later array replaces an earlier scalar", async () => {
		const a: Attributes = new Map([["scopes", "corrupted"]]);
		const b: Attributes = new Map([["scopes", ["read:user"]]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("scopes")).toEqual(["read:user"]);
	});

	it("merges different keys from multiple collectors", async () => {
		const a: Attributes = new Map([["userId", "1"]]);
		const b: Attributes = new Map([["scopes", ["read:user"]]]);
		const pipeline = new AttributePipeline([makeCollector(a), makeCollector(b)]);
		const result = await pipeline.collect(stubContext);
		expect(result.get("userId")).toBe("1");
		expect(result.get("scopes")).toEqual(["read:user"]);
	});

	it("runs collectors in parallel", async () => {
		const order: number[] = [];
		const slow: AttributeCollector = {
			collect: async () => {
				await new Promise((r) => setTimeout(r, 50));
				order.push(1);
				return new Map([["a", "1"]]);
			},
		};
		const fast: AttributeCollector = {
			collect: async () => {
				order.push(2);
				return new Map([["b", "2"]]);
			},
		};
		const pipeline = new AttributePipeline([slow, fast]);
		await pipeline.collect(stubContext);
		expect(order).toEqual([2, 1]);
	});
});
