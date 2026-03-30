import { describe, it, expect } from "vitest";
import { DotNotationResourceParser } from "../DotNotationResourceParser.mjs";

describe("DotNotationResourceParser", () => {
	const parser = new DotNotationResourceParser();

	it("parses simple type:id", () => {
		const r = parser.parse("project:1");
		expect(r.raw).toBe("project:1");
		expect(r.resourceType).toBe("project");
		expect(r.resourceId).toBe("1");
	});

	it("parses type-only (no id)", () => {
		const r = parser.parse("user");
		expect(r.raw).toBe("user");
		expect(r.resourceType).toBe("user");
		expect(r.resourceId).toBeUndefined();
	});

	it("parses nested type:id.type:id", () => {
		const r = parser.parse("project:1.member:2");
		expect(r.raw).toBe("project:1.member:2");
		expect(r.resourceType).toBe("project_member");
		expect(r.resourceId).toBe("2");
	});

	it("parses nested type:id.type (last has no id)", () => {
		const r = parser.parse("project:1.member");
		expect(r.raw).toBe("project:1.member");
		expect(r.resourceType).toBe("project_member");
		expect(r.resourceId).toBeUndefined();
	});

	it("trims whitespace", () => {
		const r = parser.parse("  project : 1 . member : 2  ");
		expect(r.resourceType).toBe("project_member");
		expect(r.resourceId).toBe("2");
	});
});
