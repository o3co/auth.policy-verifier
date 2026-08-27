// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * One reader for the numeric knobs an operator sets on a config block.
 *
 * Every such knob arrives the same way and fails the same way: absent (take the
 * default), a number, or the string a HOCON env substitution delivers — and a
 * value that is not a whole number in range must be refused rather than passed
 * to a library that ignores unusable options and quietly applies its own
 * default. The JWKS fetch bounds (#109) and the token lifetime bounds (#110)
 * both need exactly that, so it is written once here rather than restated per
 * knob, and the rejection message has a single shape operators learn once.
 *
 * Dependency-free on purpose: `AppConfigSchema` sits upstream of this, so
 * config-only consumers must not pull jose or express in behind it.
 */

/** How one numeric knob is read: where it lives, what it defaults to, what it admits. */
export interface BoundSpec {
	/** Config key as the operator wrote it, e.g. `"jwksTimeoutMs"`. */
	field: string;
	/** Config path of the block at the calling boundary, e.g. `"oauth.jwt"`. */
	path: string;
	/** Value taken when the key is absent. */
	fallback: number;
	/** Smallest accepted value. */
	minimum: number;
	/** Largest accepted value, for a knob bounded above; unbounded when omitted. */
	maximum?: number;
	/** Unit named in the rejection message, e.g. `"milliseconds"`. */
	unit: string;
}

/** Renders a rejected value for an error message: `JSON.stringify` turns NaN into `null`. */
export function describeValue(value: unknown): string {
	if (typeof value === "string") {
		return JSON.stringify(value);
	}
	if (value === null || typeof value !== "object") {
		return String(value);
	}
	return Array.isArray(value) ? "an array" : "an object";
}

/**
 * Phrases the accepted range the way the rejection message states it. A knob
 * bounded above names its endpoints, since "positive" says nothing about the
 * ceiling the operator just exceeded.
 */
function describeRange({ minimum, maximum, unit }: BoundSpec): string {
	if (maximum !== undefined) {
		return `an integer between ${minimum} and ${maximum} ${unit}`;
	}
	const requirement = minimum > 0 ? "a positive integer" : "a non-negative integer";
	return `${requirement} number of ${unit}`;
}

/**
 * Reads one bound, coercing the string form on the way. Only numbers and
 * strings are coerced: `Number(true)` is 1 and `Number(null)` is 0, so running
 * anything else through `Number` would invent a bound the operator never wrote.
 * Non-integers, NaN and Infinity are refused for the same reason the schema
 * refuses them — a bound that cannot be stated in whole units is a mistake, and
 * `Infinity` is precisely the unbounded case these knobs exist to prevent.
 */
export function resolveBound(value: unknown, spec: BoundSpec): number {
	if (value === undefined) {
		return spec.fallback;
	}
	const numeric =
		typeof value === "number" || typeof value === "string" ? Number(value) : Number.NaN;
	if (
		!Number.isInteger(numeric) ||
		numeric < spec.minimum ||
		(spec.maximum !== undefined && numeric > spec.maximum)
	) {
		throw new Error(
			`${spec.path}.${spec.field} must be ${describeRange(spec)}, got ${describeValue(value)}`,
		);
	}
	return numeric;
}
