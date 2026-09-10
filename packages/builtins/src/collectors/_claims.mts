// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Which claim carries the scopes, and how its value is read (#219). Shared by
 * the collector that promotes scopes and the rule collector that has to know
 * whether a token asserted any, so the two cannot disagree about a token.
 */

/** The claim RFC 8693 §4.2 / RFC 9068 §2.2.3 name, and the default. */
export const DEFAULT_SCOPE_CLAIM = "scope";

/**
 * Resolves a `claim` option: absent means `fallback`, a non-empty string names
 * the claim, anything else — an empty string, a number, an explicit `null` — is
 * refused at construction. `null` is not "unset": a `null` in a config was
 * produced rather than written (an unrendered template, a missing env var), and
 * reading it as the default would silently point the collector elsewhere.
 */
export function resolveClaimName(collector: string, raw: unknown, fallback: string): string {
	if (raw === undefined) return fallback;
	if (typeof raw !== "string" || raw === "") {
		throw new Error(`${collector}: claim must be a non-empty string`);
	}
	return raw;
}

/**
 * Reads a scope claim as a list. The OAuth `scope` claim is a space-delimited
 * string; Okta's `scp` and Auth0's `permissions` are arrays of strings. Either
 * shape yields the non-empty entries. Anything else — absent, a number, a list
 * carrying a non-string — asserts no capability at all, the way a non-string
 * `scope` never did: fail closed rather than pick the strings out of a value
 * that is not a scope list.
 */
export function scopesFrom(value: unknown): string[] {
	if (typeof value === "string") return value.split(" ").filter(Boolean);
	if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) {
		return value.filter(Boolean);
	}
	return [];
}
