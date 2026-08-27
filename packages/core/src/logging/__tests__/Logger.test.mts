// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { consoleLogger } from "../consoleLogger.mjs";
import type { EventLogger, Logger } from "../Logger.mjs";

describe("Logger interface contract", () => {
	it("consoleLogger satisfies the Logger interface with all 6 levels + child", () => {
		expect(typeof consoleLogger.trace).toBe("function");
		expect(typeof consoleLogger.debug).toBe("function");
		expect(typeof consoleLogger.info).toBe("function");
		expect(typeof consoleLogger.warn).toBe("function");
		expect(typeof consoleLogger.error).toBe("function");
		expect(typeof consoleLogger.fatal).toBe("function");
		expect(typeof consoleLogger.child).toBe("function");
	});

	it("Logger interface accepts a structurally complete implementation (compile-time check)", () => {
		// If `Logger` is missing any of the 6 methods + child, this object literal
		// assignment fails at compile time via excess-property checks.
		// Bound to `Logger` rather than `as any` to keep the contract enforced.
		const candidate: Logger = {
			trace: () => {},
			debug: () => {},
			info: () => {},
			warn: () => {},
			error: () => {},
			fatal: () => {},
			child(_bindings) {
				return candidate;
			},
		};
		expect(candidate.warn).toBeTypeOf("function");
	});

	it("EventLogger demands info as well as warn and error (compile-time check)", () => {
		// #111: the per-decision audit line is emitted on the SUCCESS path, so the
		// narrow port a seam is willing to demand of a caller needs a non-failure
		// level. Excess-property checking on this literal is what enforces the
		// method set — remove `info` from the interface and this stops compiling.
		const candidate: EventLogger = {
			info: () => {},
			warn: () => {},
			error: () => {},
		};
		expect(candidate.info).toBeTypeOf("function");
	});

	it("a full Logger satisfies EventLogger, so one host logger serves both seams", () => {
		const sink: EventLogger = consoleLogger;
		expect(sink.info).toBeTypeOf("function");
		expect(sink.warn).toBeTypeOf("function");
		expect(sink.error).toBeTypeOf("function");
	});

	it("Logger.child returns a Logger (structural recursion)", () => {
		const child = consoleLogger.child({ requestId: "r1" });
		expect(typeof child.trace).toBe("function");
		expect(typeof child.debug).toBe("function");
		expect(typeof child.info).toBe("function");
		expect(typeof child.warn).toBe("function");
		expect(typeof child.error).toBe("function");
		expect(typeof child.fatal).toBe("function");
		expect(typeof child.child).toBe("function");
	});
});
