import { createHash } from "node:crypto";

/**
 * Shared validation helpers for attribute-based rule constructors.
 */

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
 * Validates that a config field used as an attribute name is a non-empty string.
 * @param className - The rule class name, used in error messages.
 * @param fieldName - The config field name ("a" or "b"), used in error messages.
 * @param value - The raw value to validate.
 * @returns The validated non-empty string.
 * @throws {Error} If value is not a non-empty string.
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
 * Format: `{type}:{count}:{hashPrefix}` — SHA-256 over a canonical serialization
 * of `values`. The canonical form is `values.map(v => JSON.stringify(String(v))).sort().join(",")`,
 * which quotes and escapes each element before joining so that values containing
 * commas (or other separator characters) cannot collide across different arrays
 * (e.g. `["a,b", "c"]` vs `["a", "b,c"]`).
 * Caller must guarantee values is a non-empty homogeneous LiteralValue[].
 */
export function computeValuesKey(values: LiteralValue[]): string {
	const elementType = typeof values[0];
	const joined = values
		.map((v) => JSON.stringify(String(v)))
		.sort()
		.join(",");
	const hash = createHash("sha256").update(joined).digest("hex").slice(0, 8);
	return `${elementType}:${values.length}:${hash}`;
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
