// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Resource, ResourceParser } from "@o3co/auth.policy-verifier.core";
import { ResourceParseError } from "@o3co/auth.policy-verifier.core";

/**
 * Characters a segment type or id may carry.
 *
 * The set is RFC 6749 §3.3 `NQCHAR` (`%x21 / %x23-5B / %x5D-7E` — printable
 * ASCII minus space, `"` and `\`) less the two structural characters `.` and
 * `:`. Anchoring it there is not arbitrary: `resourceType` is concatenated into
 * the `{action}:{resourceType}` scope that `ResourceActionScopeRuleCollector`
 * requires, so a type that cannot appear in a scope value is a type no issuer
 * could ever grant.
 */
const SEGMENT_TOKEN = /^[\x21\x23-\x2D\x2F-\x39\x3B-\x5B\x5D-\x7E]+$/;

/** One `type[:id]` segment after validation. */
interface Segment {
	type: string;
	id?: string;
}

/**
 * Resource parser for dot-separated, colon-qualified identifiers such as
 * `"org:123.project:abc.document:42"`.
 *
 * ## Grammar
 *
 * ```text
 * resource = segment *( "." segment )
 * segment  = type [ ":" id ]
 * type     = 1*tchar
 * id       = 1*tchar
 * tchar    = %x21 / %x23-2D / %x2F-39 / %x3B-5B / %x5D-7E
 *            ; RFC 6749 NQCHAR less "." and ":"
 * ```
 *
 * `resourceType` is the segment types joined with `.`; `resourceId` is the id
 * of the last segment, if it has one. Anything the grammar does not accept
 * raises a {@link ResourceParseError} — the parser never repairs its input.
 *
 * ## Why nothing is rewritten
 *
 * `resourceType` is the authorization namespace: scope rules authorize it, so
 * two distinct resources that parse to the same type are authorized
 * identically, and a caller can reach resource A through a grant written for
 * resource B. Every rewrite the parser could perform is a way for that to
 * happen, so it performs none:
 *
 * - **The `.` separator is preserved.** Joining types with `_` collapsed the
 *   nested type `a.b` and the flat type literally named `a_b` onto one string.
 *   `.` is reserved as the separator and cannot occur inside a type, so the
 *   sequence of types round-trips: distinct type sequences are distinct
 *   `resourceType`s. `_` is now an ordinary type character.
 * - **Empty segments are refused.** `a..b` used to parse, and every input with
 *   a repeated `.` landed in whatever namespace the empty types produced.
 * - **Extra `:` components are refused, not truncated.** `a:1:2` used to be
 *   read as `a:1` with the tail silently dropped, so a deliberately narrowed
 *   identifier widened into the broader one.
 * - **Whitespace is refused, not trimmed.** Trimming made `project : 1` and
 *   `project:1` one resource for scope rules while
 *   `ResourceActionPermissionRuleCollector`, which reads `raw`, still saw two.
 *
 * This is the same principle `HasScope` applies to scope values: compare what
 * was written, never a normalized guess at what was meant.
 *
 * An id that needs `.`, `:` or a character outside the set must be encoded by
 * the caller (percent-encoding round-trips through this grammar) or handled by
 * a `ResourceParser` written for that syntax.
 */
export class DotNotationResourceParser implements ResourceParser {
	parse(raw: string): Resource {
		const segments = raw.split(".").map((segment, index) => parseSegment(raw, segment, index + 1));

		return {
			raw,
			// Safe because `.` cannot occur inside a type: the join is injective
			// over the sequence of types.
			resourceType: segments.map((segment) => segment.type).join("."),
			// `split` always yields at least one element, so there is a last segment.
			resourceId: segments[segments.length - 1].id,
		};
	}
}

/** Validates one `type[:id]` segment, or explains why it is not one. */
function parseSegment(raw: string, segment: string, position: number): Segment {
	const parts = segment.split(":");
	if (parts.length > 2) {
		throw new ResourceParseError(
			raw,
			`segment ${position} has more than one ":"; a segment is "type" or "type:id"`,
		);
	}

	const [type, id] = parts;
	assertToken(raw, type, position, "type");
	if (id !== undefined) {
		assertToken(raw, id, position, "id");
	}

	return id === undefined ? { type } : { type, id };
}

/** Rejects an empty or out-of-grammar type/id, naming which part of which segment. */
function assertToken(raw: string, value: string, position: number, part: "type" | "id"): void {
	if (value === "") {
		throw new ResourceParseError(raw, `segment ${position} has an empty ${part}`);
	}
	if (!SEGMENT_TOKEN.test(value)) {
		throw new ResourceParseError(
			raw,
			`segment ${position} ${part} carries a character outside the allowed set ` +
				`(printable ASCII except space, '"', "\\", "." and ":")`,
		);
	}
}
