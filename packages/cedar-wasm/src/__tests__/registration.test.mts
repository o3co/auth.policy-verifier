// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Nothing of this package is imported statically here, and that is the point:
 * the first assertions look at cedar's engine registry *before* the package
 * loads, so the property the design rests on — the engine is registered by
 * loading the package, not by anything a deployment calls — is observed
 * rather than assumed.
 */

import { describe, expect, it } from "vitest";

describe("the wasm engine is registered by loading the package", () => {
	it("is selectable by name and by default only once the package is imported", async () => {
		// Cedar is loaded first, by package specifier — the same instance this
		// package resolves. A registration into some other copy would not be
		// visible here.
		const cedar = await import("@o3co/auth.policy-verifier.cedar");
		expect(cedar.registeredCedarEngines()).not.toContain("wasm");
		expect(() => cedar.resolveCedarEngine()).toThrow(/@o3co\/auth\.policy-verifier\.cedar-wasm/);
		expect(() => cedar.resolveCedarEngine("wasm")).toThrow(
			/@o3co\/auth\.policy-verifier\.cedar-wasm/,
		);

		const wasm = await import("../index.mjs");

		expect(cedar.registeredCedarEngines()).toContain("wasm");
		expect(cedar.resolveCedarEngine()).toBe(wasm.cedarWasmEngine);
		expect(cedar.resolveCedarEngine("wasm")).toBe(wasm.cedarWasmEngine);
		expect(wasm.cedarWasmEngine.name).toBe(wasm.CEDAR_WASM_ENGINE_NAME);
	});

	it("tolerates being registered again — a second import path is not a second engine", async () => {
		const cedar = await import("@o3co/auth.policy-verifier.cedar");
		const wasm = await import("../index.mjs");
		expect(() => cedar.registerCedarEngine(wasm.cedarWasmEngine)).not.toThrow();
		expect(cedar.registeredCedarEngines().filter((name) => name === "wasm")).toHaveLength(1);
	});
});
