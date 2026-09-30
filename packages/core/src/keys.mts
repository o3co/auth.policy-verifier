// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Core's attribute-key vocabulary and the registry of reserved keys. A package
 * reserves the keys it owns here (`reserveAttributeKeys`), so that a collector
 * promoting caller- or claim-supplied data can refuse a reserved key, name its
 * owner and suggest an unreserved one.
 */

// Canonical attribute keys used by built-in collectors and rules. Reference
// these constants rather than raw strings.

export const ATTR_SCOPES = "scopes" as const;
export const ATTR_PERMISSIONS = "permissions" as const;
export const ATTR_ROLES = "roles" as const;
export const ATTR_USER_ID = "userId" as const;
export const ATTR_CLIENT_ID = "clientId" as const;

/** The npm package name core reserves its own vocabulary under. */
export const CORE_ATTRIBUTE_KEY_OWNER = "@o3co/auth.policy-verifier.core" as const;

/** One package's claim on one attribute key. */
export interface AttributeKeyReservation {
	/** The reserved key. */
	readonly key: string;
	/** npm package name of the package whose vocabulary this key belongs to. */
	readonly owner: string;
	/** One clause naming who writes the key, quoted verbatim by a refusal. */
	readonly reason?: string;
}

/** What {@link reserveAttributeKeys} takes: one package, its keys, and why. */
export interface AttributeKeyReservationRequest {
	/** npm package name of the reserving package — `import.meta` has no such thing, so state it. */
	readonly owner: string;
	/** The keys that package writes and no caller-supplied mapping may target. */
	readonly keys: Iterable<string>;
	/** One clause naming who writes them, quoted verbatim by a refusal. */
	readonly reason?: string;
}

/** key → reservation. The registry's single source of truth. */
const reservations = new Map<string, AttributeKeyReservation>();

/**
 * The keys, as one set, for the `has` check a guard actually performs.
 *
 * Kept in step with {@link reservations} by `reserveAttributeKeys`, which is
 * the only writer of either.
 */
const reservedKeys = new Set<string>();

/**
 * Every reserved attribute key: the vocabulary the engine and its packages
 * decide from, and so the keys a collector promoting caller-supplied data must
 * refuse to write.
 *
 * **This set is live, not a snapshot.** It starts as core's five and grows as
 * packages call {@link reserveAttributeKeys} (`packages/cedar` reserves four
 * `request*` keys when it loads). Read it when you need the verdict; a copy
 * taken at module scope misses every package that loads after yours.
 *
 * A reserved key's value is the deployment's to write, never the caller's.
 * Under the default server, `scope`, `sub` and `azp` of the signature-verified
 * token become {@link ATTR_SCOPES}, {@link ATTR_USER_ID} and
 * {@link ATTR_CLIENT_ID} (AGENTS.md tabulates the mapping).
 * `AttributePipeline` unions array-valued entries across collectors, so a
 * caller-supplied write to one of these keys silently extends the deployment's
 * value; a disagreeing scalar throws `AttributeConflictError`, which denies.
 * Where the owning collector writes its key only sometimes (`packages/cedar`
 * omits `requestResourceId` for an id-less resource), there is no second
 * writer and the caller's value stands alone. See `AttributePipeline`'s merge
 * doc comment and docs/extending.md, "The trust boundary".
 *
 * `RequestContextAttributeCollector` (builtins) consults this for every key;
 * `PayloadClaimAttributeCollector` (builtins) consults it for the keys other
 * packages own and lets a verified claim land on core's five. The line is the
 * trust boundary, not the source: core's five are written from what the
 * deployment established (verified claims or its own configuration), never
 * from the caller's request.
 */
export const RESERVED_ATTRIBUTE_KEYS: ReadonlySet<string> = reservedKeys;

/**
 * Reserves the attribute keys a package owns, so that a collector promoting
 * caller-supplied data refuses to write them.
 *
 * **Call it at module scope, beside the `ATTR_*` constants.** A composition can
 * only name a package's collectors by importing the package, so a reservation
 * made at module load is in place before any collector can be constructed.
 * Reserving in `Module.init` or a collector factory would be later than that,
 * and `init` would miss a library consumer that never calls `createApp`.
 *
 * Reserving the same key again under the same `owner` is a no-op, so a module
 * evaluated more than once is not a failure. A second owner for one key is
 * refused.
 *
 * The registry is this module's state. A dependency graph carrying two copies
 * of core carries two registries, and a reservation in one is invisible to a
 * guard reading the other; dedupe core if a resolver produces that.
 *
 * ```ts
 * export const ATTR_REQUEST_ACTION = "requestAction" as const;
 *
 * reserveAttributeKeys({
 *   owner: "@example/policy-plugin",
 *   keys: [ATTR_REQUEST_ACTION],
 *   reason: "written by RequestFactsCollector from the parsed request",
 * });
 * ```
 *
 * @throws Error if `owner` or a key is not a non-empty string, if `keys` is not
 * a non-string iterable, or if any key is already reserved by another package.
 * Nothing is registered when it throws.
 */
export function reserveAttributeKeys(request: AttributeKeyReservationRequest): void {
	const { owner, keys, reason } = request ?? {};
	if (typeof owner !== "string" || owner.length === 0) {
		throw new Error(
			`reserveAttributeKeys: owner must be a non-empty package name, got ${describe(owner)}`,
		);
	}

	// Validated and checked for conflicts in full before anything is written.
	if (typeof keys === "string" || keys == null || typeof keys[Symbol.iterator] !== "function") {
		throw new Error("reserveAttributeKeys: keys must be a non-string iterable");
	}
	const pending: AttributeKeyReservation[] = [];
	for (const key of keys) {
		if (typeof key !== "string" || key.length === 0) {
			throw new Error(
				`reserveAttributeKeys: ${owner} supplied a key that is not a non-empty string, got ${describe(key)}`,
			);
		}
		const held = reservations.get(key);
		if (held === undefined) {
			pending.push(reason === undefined ? { key, owner } : { key, owner, reason });
			continue;
		}
		if (held.owner !== owner) {
			throw new Error(
				`reserveAttributeKeys: attribute key "${key}" is already reserved by ${held.owner}, ` +
					`so ${owner} cannot also reserve it. An attribute key names one package's vocabulary; ` +
					"two owners leave no answer to which of them writes it. Rename one of the two keys.",
			);
		}
	}

	for (const reservation of pending) {
		reservations.set(reservation.key, reservation);
		reservedKeys.add(reservation.key);
	}
}

/**
 * Who owns `key`, or `undefined` if nobody has reserved it. A refusal uses it to
 * name the package the key belongs to.
 */
export function attributeKeyReservation(key: string): AttributeKeyReservation | undefined {
	return reservations.get(key);
}

/** Prefixes a suggested rename is drawn from, in order of preference. */
const SUGGESTION_PREFIXES = ["request", "caller", "context"] as const;

/**
 * A key like `key` that no package has reserved — the rename a refusal advises.
 *
 * Every candidate is checked against the registry, so the advice does not
 * propose a key another package has reserved (`packages/cedar` owns
 * `request*` keys). A prefix the key already carries is skipped rather than
 * doubled. Terminates: the numbered fallback produces unboundedly many distinct
 * candidates and only finitely many keys are ever reserved.
 */
export function suggestUnreservedAttributeKey(key: string): string {
	for (const prefix of SUGGESTION_PREFIXES) {
		if (key.startsWith(prefix)) continue;
		const candidate = `${prefix}${capitalize(key)}`;
		if (!reservedKeys.has(candidate)) return candidate;
	}
	let suffix = 1;
	let candidate = `${key}Attribute`;
	while (reservedKeys.has(candidate)) {
		suffix += 1;
		candidate = `${key}Attribute${suffix}`;
	}
	return candidate;
}

function capitalize(value: string): string {
	return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

function describe(value: unknown): string {
	if (value === null) return "null";
	if (Array.isArray(value)) return "array";
	if (typeof value === "string") return JSON.stringify(value);
	return typeof value;
}

// Core's own five, reserved through the same call every other package makes.
// Beside the constants, so that a new `ATTR_*` is reserved in the same edit.
reserveAttributeKeys({
	owner: CORE_ATTRIBUTE_KEY_OWNER,
	keys: [ATTR_SCOPES, ATTR_PERMISSIONS, ATTR_ROLES, ATTR_USER_ID, ATTR_CLIENT_ID],
	reason:
		"the engine's own vocabulary, written by the deployment — from the signature-verified token for scopes/userId/clientId, from configuration for roles/permissions",
});
