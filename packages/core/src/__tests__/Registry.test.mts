import { describe, expect, it } from "vitest";
import { Registry } from "../modules/Registry.mjs";

describe("Registry", () => {
	it("registers and retrieves an instance by name", () => {
		const registry = new Registry<string>();
		registry.register("foo", "bar");
		expect(registry.get("foo")).toBe("bar");
	});

	it("reports whether a name is registered", () => {
		const registry = new Registry<number>();
		expect(registry.has("x")).toBe(false);
		registry.register("x", 42);
		expect(registry.has("x")).toBe(true);
	});

	it("throws on get for unregistered name", () => {
		const registry = new Registry<string>();
		expect(() => registry.get("missing")).toThrow(
			'Registry: "missing" is not registered',
		);
	});

	it("throws on duplicate registration", () => {
		const registry = new Registry<string>();
		registry.register("dup", "first");
		expect(() => registry.register("dup", "second")).toThrow(
			'Registry: "dup" is already registered',
		);
	});

	it("returns all entries", () => {
		const registry = new Registry<number>();
		registry.register("a", 1);
		registry.register("b", 2);
		expect(registry.entries()).toEqual([
			["a", 1],
			["b", 2],
		]);
	});
});
