// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ResourceParseError } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { DotNotationResourceParser } from "#/resource/DotNotationResourceParser.mjs";

describe("DotNotationResourceParser", () => {
	const parser = new DotNotationResourceParser();

	describe("accepted grammar", () => {
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

		it("keeps the dot as the segment separator in the derived type", () => {
			const r = parser.parse("project:1.member:2");
			expect(r.raw).toBe("project:1.member:2");
			expect(r.resourceType).toBe("project.member");
			expect(r.resourceId).toBe("2");
		});

		it("parses nested type:id.type (last has no id)", () => {
			const r = parser.parse("project:1.member");
			expect(r.raw).toBe("project:1.member");
			expect(r.resourceType).toBe("project.member");
			expect(r.resourceId).toBeUndefined();
		});

		it("takes the id from the last segment only", () => {
			expect(parser.parse("org:1.project:2.document:3").resourceId).toBe("3");
			expect(parser.parse("org:1.project:2.document").resourceId).toBeUndefined();
		});

		it("treats _ as an ordinary type character, not a separator", () => {
			const r = parser.parse("project_member:2");
			expect(r.resourceType).toBe("project_member");
			expect(r.resourceId).toBe("2");
		});

		it("accepts the punctuation an opaque id tends to carry", () => {
			// A UUID, a slug and a percent-encoded value all stay intact.
			expect(parser.parse("doc:3f1a-9c2e").resourceId).toBe("3f1a-9c2e");
			expect(parser.parse("doc:a_b~c").resourceId).toBe("a_b~c");
			expect(parser.parse("doc:did%3Aexample%3A123").resourceId).toBe("did%3Aexample%3A123");
		});

		it("returns raw verbatim", () => {
			expect(parser.parse("Org:A.Project:B").raw).toBe("Org:A.Project:B");
		});

		it("is case-preserving, like the scope it derives", () => {
			expect(parser.parse("Project:1").resourceType).toBe("Project");
			expect(parser.parse("project:1").resourceType).toBe("project");
		});
	});

	describe("distinct resources never collide into one type", () => {
		// The regression this grammar exists for: the derived resourceType is what
		// scope rules authorize, so two distinct resource strings that produce the
		// same type are authorized identically.
		it("keeps a flat type named with _ apart from a nested type", () => {
			expect(parser.parse("a.b").resourceType).toBe("a.b");
			expect(parser.parse("a_b").resourceType).toBe("a_b");
			expect(parser.parse("a.b").resourceType).not.toBe(parser.parse("a_b").resourceType);
		});

		it("maps every distinct type sequence to a distinct type string", () => {
			const inputs = ["a.b", "a_b", "a.b.c", "a_b.c", "a.b_c", "a_b_c", "a", "a-b", "a.b.c.d"];
			const types = inputs.map((raw) => parser.parse(raw).resourceType);

			// Under the old `_` join, "a.b"/"a_b", "a.b.c"/"a_b.c"/"a.b_c"/"a_b_c"
			// all collapsed onto one string. The join character is now reserved.
			expect(new Set(types).size).toBe(inputs.length);
		});

		it("derives the type from segment types only, never from ids", () => {
			// Ids identify the instance; the type is what is authorized. Two
			// instances of one type share a type — that is the point — but no id
			// content can change which type a string lands in.
			expect(parser.parse("project:1.member:2").resourceType).toBe("project.member");
			expect(parser.parse("project:x_y.member:z").resourceType).toBe("project.member");
		});
	});

	describe("rejected input", () => {
		const rejected: ReadonlyArray<readonly [string, string]> = [
			["", "the empty string"],
			["a..b", "an empty inner segment"],
			[".a", "an empty leading segment"],
			["a.", "an empty trailing segment"],
			[".", "nothing but a separator"],
			[":1", "an empty type"],
			["a:1.:2", "an empty type in a later segment"],
			["a:", "an empty id"],
			["a:1.b:", "an empty id in the last segment"],
			["a:1:2", "a second colon in one segment"],
			["a:1:2:3", "several extra colons"],
			["a.b:1:2", "an extra colon in a later segment"],
			["  project:1  ", "surrounding whitespace"],
			["project : 1", "whitespace around the colon"],
			["project:1 . member:2", "whitespace around the separator"],
			["project member", "an inner space"],
			["project\t:1", "a tab"],
			["project\n", "a newline"],
			['a"b', "a double quote, which no OAuth scope value may carry"],
			["a\\b", "a backslash, which no OAuth scope value may carry"],
			["プロジェクト", "a non-ASCII type"],
			["doc:é", "a non-ASCII id"],
			["a\u0000b", "a NUL"],
		];

		for (const [raw, why] of rejected) {
			it(`refuses ${why}: ${JSON.stringify(raw)}`, () => {
				expect(() => parser.parse(raw)).toThrow(ResourceParseError);
			});
		}

		it("refuses rather than truncating an extra colon component", () => {
			// The old parser destructured on ":" and dropped everything past the
			// second part, so "a:1:2" silently became the resource "a:1".
			expect(() => parser.parse("a:1:2")).toThrow(ResourceParseError);
		});

		it("names the offending string verbatim on the error", () => {
			try {
				parser.parse("a..b");
				expect.unreachable("expected a ResourceParseError");
			} catch (error) {
				expect(error).toBeInstanceOf(ResourceParseError);
				expect((error as ResourceParseError).raw).toBe("a..b");
				expect((error as ResourceParseError).message).toContain('"a..b"');
			}
		});

		it("says which segment was at fault", () => {
			expect(() => parser.parse("a.b..d")).toThrow(/segment 3/);
			expect(() => parser.parse("a:1:2")).toThrow(/segment 1/);
		});
	});
});
