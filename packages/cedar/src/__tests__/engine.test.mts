// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CedarEngine } from "../engine.mjs";

/** A fresh registry per test: the module holds it at module scope, as production does. */
async function fresh() {
	vi.resetModules();
	return import("../engine.mjs");
}

function engine(name: string): CedarEngine {
	return {
		name,
		load: () => ({
			async: false,
			isAuthorized: () => ({ decision: "deny", reason: [], errors: [] }),
		}),
	};
}

describe("registerCedarEngine", () => {
	beforeEach(() => vi.resetModules());

	it("registers under the engine's name, in order", async () => {
		const { registerCedarEngine, registeredCedarEngines } = await fresh();
		expect(registeredCedarEngines()).toEqual([]);
		registerCedarEngine(engine("http"));
		registerCedarEngine(engine("wasm"));
		expect(registeredCedarEngines()).toEqual(["http", "wasm"]);
	});

	it("needs a name and a load function", async () => {
		const { registerCedarEngine, registeredCedarEngines } = await fresh();
		expect(() => registerCedarEngine(engine(""))).toThrow(/non-empty name/);
		// From JavaScript the type is no guard: refuse at the registration site.
		expect(() => registerCedarEngine({ name: "broken" } as unknown as CedarEngine)).toThrow(
			/engine "broken" needs a load function/,
		);
		expect(registeredCedarEngines()).toEqual([]);
	});

	it("is a no-op for the same engine twice, and refuses a different one under a taken name", async () => {
		const { registerCedarEngine, registeredCedarEngines } = await fresh();
		const wasm = engine("wasm");
		registerCedarEngine(wasm);
		expect(() => registerCedarEngine(wasm)).not.toThrow();
		expect(registeredCedarEngines()).toEqual(["wasm"]);
		expect(() => registerCedarEngine(engine("wasm"))).toThrow(
			/a different engine is already registered as "wasm"/,
		);
	});
});

describe("resolveCedarEngine — the selection table", () => {
	it("absent: nothing registered refuses, naming the wasm package", async () => {
		const { resolveCedarEngine } = await fresh();
		expect(() => resolveCedarEngine()).toThrow(
			/no Cedar engine is registered — import "@o3co\/auth\.policy-verifier\.cedar-wasm"/,
		);
		expect(() => resolveCedarEngine()).toThrow(/registers another engine \(registerCedarEngine\)/);
		expect(() => resolveCedarEngine()).toThrow(/\(none registered\)/);
	});

	it("absent: wasm wins over http when both are registered", async () => {
		const { registerCedarEngine, resolveCedarEngine } = await fresh();
		const http = engine("http");
		const wasm = engine("wasm");
		registerCedarEngine(http);
		registerCedarEngine(wasm);
		expect(resolveCedarEngine()).toBe(wasm);
	});

	it("absent: http when wasm was not imported", async () => {
		const { registerCedarEngine, resolveCedarEngine } = await fresh();
		const http = engine("http");
		registerCedarEngine(http);
		expect(resolveCedarEngine()).toBe(http);
	});

	it("absent: an engine outside the preference list is never chosen by default, and the error says to name it", async () => {
		const { registerCedarEngine, resolveCedarEngine } = await fresh();
		registerCedarEngine(engine("custom"));
		expect(() => resolveCedarEngine()).toThrow(
			/none of the engines chosen by default \(wasm, http\) is registered — set engine to one of the registered ones \(registered: custom\)/,
		);
	});

	it("named: an explicit choice wins over the preference", async () => {
		const { registerCedarEngine, resolveCedarEngine } = await fresh();
		const http = engine("http");
		registerCedarEngine(engine("wasm"));
		registerCedarEngine(http);
		expect(resolveCedarEngine("http")).toBe(http);
	});

	it("named wasm without the import refuses, naming the package that registers it", async () => {
		const { registerCedarEngine, resolveCedarEngine } = await fresh();
		registerCedarEngine(engine("http"));
		expect(() => resolveCedarEngine("wasm")).toThrow(
			/engine "wasm" is not registered — import "@o3co\/auth\.policy-verifier\.cedar-wasm"/,
		);
		expect(() => resolveCedarEngine("wasm")).toThrow(/\(registered: http\)/);
	});

	it("named unknown refuses, listing what is registered", async () => {
		const { registerCedarEngine, resolveCedarEngine } = await fresh();
		registerCedarEngine(engine("wasm"));
		expect(() => resolveCedarEngine("opa")).toThrow(
			/engine "opa" is not a registered Cedar engine \(registered: wasm\)/,
		);
	});

	it("refuses a non-string or empty name", async () => {
		const { resolveCedarEngine } = await fresh();
		expect(() => resolveCedarEngine(7)).toThrow(/engine must be a non-empty string, got 7/);
		expect(() => resolveCedarEngine("")).toThrow(/engine must be a non-empty string/);
	});
});
