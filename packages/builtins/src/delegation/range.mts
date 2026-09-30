// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * A delegated token's range, as the provider-verifier claims contract states
 * it (o3co/auth, docs/claims-contract.md): RFC 9396 `authorization_details`
 * entries of one type, each carrying a path in the grammar
 * `(type(:id)?.)*action`, and the rule by which an entry contains a requested
 * path. Shared by `DelegationRangeCollector`, which reads the range out of
 * the token, `DelegationRangeRuleCollector`, which decides whether a token
 * has one, and `WithinDelegationRange`, which decides containment. Nothing is
 * normalized: a path is compared as written, as `HasScope` compares scopes.
 * The attribute key the range travels under is `../keys.mts`'s.
 */

/** The claim RFC 9396 carries the entries in, and the default. */
export const DEFAULT_AUTHORIZATION_DETAILS_CLAIM = "authorization_details";

/** One element of a path: a type, and an id when the path names one. */
export interface RangeElement {
	type: string;
	id?: string;
}

/** A type, or the action that ends a path. */
const NAME = /^[a-z][a-z0-9_]*$/;
/** An id: unreserved characters, anything else percent-encoded in upper-case hex. */
const ID = /^(?:[A-Za-z0-9_~-]|%[0-9A-F]{2})+$/;

/**
 * Reads `path` as `(type(:id)?.)*action`, or `null` when it is not one:
 *
 * - `type` and `action` are `[a-z][a-z0-9_]*`;
 * - `id` is `[A-Za-z0-9_~-]`, any other character percent-encoded with
 *   upper-case hex, so each id has one spelling to compare;
 * - the action, the last element, carries no id.
 */
export function parseRangePath(path: string): RangeElement[] | null {
	if (typeof path !== "string" || path === "") return null;
	const parts = path.split(".");
	const elements: RangeElement[] = [];
	for (const [index, part] of parts.entries()) {
		const pieces = part.split(":");
		if (pieces.length > 2) return null;
		const [type, id] = pieces;
		if (!NAME.test(type)) return null;
		if (id === undefined) {
			elements.push({ type });
			continue;
		}
		if (index === parts.length - 1 || !ID.test(id)) return null;
		elements.push({ type, id });
	}
	return elements;
}

/**
 * The requested path — the raw resource, then the action — or `null` when the
 * action is not one action of the grammar. The action is checked on its own
 * before the join: an action of several elements (`report.delete`) would
 * re-split the joined path, so a request on the parent `project:p1` would
 * read as one on `project:p1.report`, which a range may contain.
 */
export function requestedRangePath(resource: string, action: string): string | null {
	return NAME.test(action) ? `${resource}.${action}` : null;
}

/**
 * Whether the range entry `entry` contains the requested `path`: a
 * segment-wise prefix of it, each element of the same type, and an element
 * that names no id containing the same type with any id. Either side outside
 * the grammar contains nothing.
 */
export function rangeContains(entry: string, path: string): boolean {
	const within = parseRangePath(entry);
	const requested = parseRangePath(path);
	if (within === null || requested === null || within.length > requested.length) return false;
	return within.every(
		(element, index) =>
			element.type === requested[index].type &&
			(element.id === undefined || element.id === requested[index].id),
	);
}

/**
 * The claim's entries of `type`, or `null` when the token has no range: the
 * claim is absent, or a list of RFC 9396 entries none of which is of the type.
 * A token cannot shed its range by spelling it badly: an entry of the type
 * counts however malformed its path, and a claim present in another shape — not
 * a list, or a list holding something that is not an entry object — is a range
 * with no entries, which contains nothing.
 */
export function entriesOfType(claim: unknown, type: string): object[] | null {
	if (claim === undefined) return null;
	if (!Array.isArray(claim) || !claim.every(isEntryObject)) return [];
	const entries = claim.filter((entry) => (entry as { type?: unknown }).type === type);
	return entries.length > 0 ? entries : null;
}

function isEntryObject(entry: unknown): entry is object {
	return typeof entry === "object" && entry !== null && !Array.isArray(entry);
}

/** The entries' paths that are in the grammar; the rest are left out, which narrows the range. */
export function rangePaths(entries: object[]): string[] {
	return entries
		.map((entry) => (entry as { path?: unknown }).path)
		.filter((path): path is string => typeof path === "string" && parseRangePath(path) !== null);
}

/** Resolves a collector's `type` option, which has no default: it is the deployment's delegation type. */
export function resolveRangeType(collector: string, raw: unknown): string {
	if (typeof raw !== "string" || raw === "") {
		throw new Error(
			`${collector}: type must be the authorization_details type the delegation range is carried under, a non-empty string`,
		);
	}
	return raw;
}
