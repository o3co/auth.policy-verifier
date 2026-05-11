// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared validation helpers for attribute-based rule constructors.
 */

/**
 * FNV-1a 64-bit non-cryptographic hash, computed with BigInt. Sync,
 * runtime-agnostic (no `node:*` imports), deterministic. Returns 16
 * lowercase hex characters, zero-padded.
 *
 * Used by `computeValuesKey` to build a stable grouping suffix for `ruleType`.
 * The 64-bit output gives ~2^32 birthday-collision bound, which is
 * effectively non-colliding for any realistic policy size and resists
 * deliberate collision construction by a hostile policy author or supply
 * chain. (A 32-bit variant was rejected during review because random short
 * strings can be made to collide within seconds, weakening evaluator
 * grouping when two distinct rules on the same attribute share a `ruleType`.)
 *
 * Iterates UTF-16 code units via `charCodeAt`. BigInt is used because
 * 64-bit multiplication overflows IEEE-754 doubles; `Math.imul` only
 * supports 32-bit. BigInt is available in every modern JavaScript runtime
 * (Node 10.4+, all evergreen browsers, Cloudflare Workers, Deno, Bun).
 */
const FNV_OFFSET_BASIS_64 = 0xcbf29ce484222325n;
const FNV_PRIME_64 = 0x100000001b3n;
const FNV_MASK_64 = 0xffffffffffffffffn;
export function fnv1a64(s: string): string {
	let hash = FNV_OFFSET_BASIS_64;
	for (let i = 0; i < s.length; i++) {
		hash ^= BigInt(s.charCodeAt(i));
		hash = (hash * FNV_PRIME_64) & FNV_MASK_64;
	}
	return hash.toString(16).padStart(16, "0");
}

export type LiteralValue = string | number | boolean;

/**
 * Returns a human-readable type label for use in error messages.
 * Distinguishes null and undefined from other types instead of returning
 * "object" or "undefined" from typeof.
 */
function describeType(value: unknown): string {
	if (value === null) return "null";
	if (value === undefined) return "undefined";
	return typeof value;
}

export type CompareOp = "lt" | "le" | "gt" | "ge";

export const COMPARE_OPS: readonly CompareOp[] = ["lt", "le", "gt", "ge"];

/**
 * Validates that a config field used as an attribute name is a non-empty string
 * that does not contain the `:` separator character used in derived `ruleType`
 * strings. Allowing `:` would let distinct configs collide on the same
 * `ruleType` (e.g. `(a="x:y", b="z")` and `(a="x", b="y:z")` both produce
 * `attr_pair_equal:x:y:z`), which the evaluator would silently OR together
 * and weaken authorization.
 * @param className - The rule class name, used in error messages.
 * @param fieldName - The config field name ("a" or "b"), used in error messages.
 * @param value - The raw value to validate.
 * @returns The validated non-empty string.
 * @throws {Error} If value is not a non-empty string, or contains `:`.
 */
export function requireAttrName(className: string, fieldName: "a" | "b", value: unknown): string {
	if (typeof value !== "string") {
		throw new Error(
			`${className}: '${fieldName}' must be a non-empty string, got ${describeType(value)}`,
		);
	}
	if (value.length === 0) {
		throw new Error(`${className}: '${fieldName}' must be a non-empty string, got empty string`);
	}
	if (value.includes(":")) {
		throw new Error(
			`${className}: '${fieldName}' must not contain ':' (reserved as ruleType separator), got '${value}'`,
		);
	}
	return value;
}

/**
 * Validates that a config field used as a literal comparison value is a
 * string, number, or boolean (i.e. a LiteralValue). NaN is rejected because
 * its comparison semantics (`NaN !== NaN` is always true, `NaN === NaN` is
 * always false) would silently invert Equal/NotEqual rules — a NotEqual(v=NaN)
 * would always pass against any numeric attribute, weakening authorization.
 * @param className - The rule class name, used in error messages.
 * @param fieldName - The config field name ("v"), used in error messages.
 * @param value - The raw value to validate.
 * @returns The validated LiteralValue.
 * @throws {Error} If value is null, undefined, of any other type, or NaN.
 */
export function requireLiteralValue(
	className: string,
	fieldName: "v",
	value: unknown,
): LiteralValue {
	if (typeof value === "string" || typeof value === "boolean") {
		return value;
	}
	if (typeof value === "number") {
		if (Number.isNaN(value)) {
			throw new Error(`${className}: '${fieldName}' must not be NaN`);
		}
		return value;
	}
	throw new Error(
		`${className}: '${fieldName}' must be string | number | boolean, got ${describeType(value)}`,
	);
}

/**
 * Validates a numeric comparison value. Rejects NaN; accepts Infinity/-Infinity.
 * @param className - The rule class name, used in error messages.
 * @param fieldName - The config field name ("v"), used in error messages.
 * @param value - The raw value to validate.
 * @returns The validated number.
 * @throws {Error} If value is not a number, or if value is NaN.
 */
export function requireNumber(className: string, fieldName: "v", value: unknown): number {
	if (typeof value !== "number") {
		throw new Error(`${className}: '${fieldName}' must be a number, got ${describeType(value)}`);
	}
	if (Number.isNaN(value)) {
		throw new Error(`${className}: '${fieldName}' must not be NaN`);
	}
	return value;
}

/**
 * Validates that a value is a non-empty, homogeneous array of LiteralValues
 * (no null/undefined elements, no NaN elements, all elements the same typeof).
 * @param className - The rule class name, used in error messages.
 * @param value - The raw value to validate.
 * @returns The validated LiteralValue array.
 * @throws {Error} If not an array, empty, contains invalid elements, has mixed types, or contains NaN.
 */
export function requireHomogeneousLiteralArray(className: string, value: unknown): LiteralValue[] {
	if (!Array.isArray(value)) {
		throw new Error(
			`${className}: 'values' must be a non-empty array of string | number | boolean, got ${describeType(value)}`,
		);
	}
	if (value.length === 0) {
		throw new Error(`${className}: 'values' must be a non-empty array`);
	}
	const seenTypes = new Set<string>();
	for (const element of value) {
		if (element === null || element === undefined) {
			throw new Error(
				`${className}: 'values' elements must be string | number | boolean, got ${describeType(element)}`,
			);
		}
		const t = typeof element;
		if (t !== "string" && t !== "number" && t !== "boolean") {
			throw new Error(
				`${className}: 'values' elements must be string | number | boolean, got ${t}`,
			);
		}
		if (t === "number" && Number.isNaN(element)) {
			throw new Error(`${className}: 'values' must not contain NaN`);
		}
		seenTypes.add(t);
	}
	if (seenTypes.size > 1) {
		const typeList = [...seenTypes].join(", ");
		throw new Error(
			`${className}: 'values' must be a homogeneous array of string | number | boolean; got mixed types [${typeList}]`,
		);
	}
	return value as LiteralValue[];
}

/**
 * Validates that a value is one of the allowed CompareOp strings.
 * @param className - The rule class name, used in error messages.
 * @param value - The raw value to validate.
 * @returns The validated CompareOp.
 * @throws {Error} If value is not a string or not one of the allowed operators.
 */
export function requireCompareOp(className: string, value: unknown): CompareOp {
	if (typeof value !== "string") {
		throw new Error(
			`${className}: 'op' must be one of ${COMPARE_OPS.join(" | ")}, got ${describeType(value)}`,
		);
	}
	if (!(COMPARE_OPS as readonly string[]).includes(value)) {
		throw new Error(`${className}: 'op' must be one of ${COMPARE_OPS.join(" | ")}, got '${value}'`);
	}
	return value as CompareOp;
}

/**
 * Validates an optional group string. Returns undefined when value is undefined;
 * throws when value is a non-string or an empty string; otherwise returns the
 * non-empty string.
 * @param className - The rule class name, used in error messages.
 * @param value - The raw value to validate.
 * @returns The validated non-empty string, or undefined.
 * @throws {Error} If value is a non-string or an empty string.
 */
export function requireOptionalGroup(className: string, value: unknown): string | undefined {
	if (value === undefined) {
		return undefined;
	}
	if (typeof value !== "string") {
		throw new Error(
			`${className}: 'group' must be a non-empty string or undefined, got ${describeType(value)}`,
		);
	}
	if (value.length === 0) {
		throw new Error(
			`${className}: 'group' must be a non-empty string or undefined, got empty string`,
		);
	}
	return value;
}

/**
 * Computes a stable cache/dedup key for an array of LiteralValues.
 * Format: `{type}:{count}:{hashPrefix}` — `hashPrefix` is a 16-hex-character
 * FNV-1a 64-bit hash over a canonical serialization of `values`. The canonical
 * form first deduplicates `values` (to mirror the Set-based semantics of
 * AttrLiteralIn / AttrLiteralNotIn — duplicates do not change the rule's
 * behavior, so they must not change its `ruleType`), then applies
 * `JSON.stringify(String(v))` to each remaining element before sorting and
 * joining with `,`. The per-element quoting prevents separator collisions
 * across different arrays (e.g. `["a,b", "c"]` vs `["a", "b,c"]`).
 * The `{count}` segment reflects the post-dedup element count.
 * Caller must guarantee values is a non-empty homogeneous LiteralValue[].
 *
 * The hash is non-cryptographic by design, but uses 64-bit output to keep
 * the birthday-collision bound (~2^32) far above any realistic policy size
 * and to resist deliberate collision construction.
 */
export function computeValuesKey(values: LiteralValue[]): string {
	const elementType = typeof values[0];
	const unique = [...new Set(values)];
	const joined = unique
		.map((v) => JSON.stringify(String(v)))
		.sort()
		.join(",");
	return `${elementType}:${unique.length}:${fnv1a64(joined)}`;
}

/**
 * Applies a numeric comparison operator between left and right.
 */
export function applyCompare<T extends number>(op: CompareOp, left: T, right: T): boolean {
	switch (op) {
		case "lt":
			return left < right;
		case "le":
			return left <= right;
		case "gt":
			return left > right;
		case "ge":
			return left >= right;
	}
}
