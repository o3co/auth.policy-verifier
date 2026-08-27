// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { ResourceParseError } from "../errors.mjs";

describe("ResourceParseError", () => {
	it("is an Error carrying the rejected string and the reason", () => {
		const error = new ResourceParseError("a..b", "segment 2 is empty; every segment needs a type");

		expect(error).toBeInstanceOf(Error);
		expect(error.name).toBe("ResourceParseError");
		expect(error.raw).toBe("a..b");
		expect(error.detail).toBe("segment 2 is empty; every segment needs a type");
	});

	it("names both the rejected string and the reason in its message", () => {
		const error = new ResourceParseError("a..b", "segment 2 is empty");

		expect(error.message).toBe('Invalid resource string "a..b": segment 2 is empty');
	});

	it("is distinguishable from an unrelated error, so a caller can map it to a 400", () => {
		expect(new ResourceParseError("x", "y")).toBeInstanceOf(ResourceParseError);
		expect(new Error("boom")).not.toBeInstanceOf(ResourceParseError);
	});
});
