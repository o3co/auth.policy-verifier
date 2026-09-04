// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Canonical attribute keys used by built-in collectors and rules. Consumers
// should reference these constants instead of raw strings so that renames stay
// centralized and TypeScript can infer literal types.

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
 * decide from, and therefore the destinations a collector promoting
 * caller-supplied data must refuse to write.
 *
 * **This set is live, not a snapshot.** It starts as core's own five and grows
 * as packages call {@link reserveAttributeKeys} — `packages/cedar` reserves
 * four `request*` keys when it loads. Read it at the moment you need the
 * verdict; copying it into a `new Set(...)` at module scope reintroduces
 * exactly the hole the registry closes, because a package that loads after
 * yours would not be in the copy.
 *
 * Under the default server three of core's five are derived from the
 * signature-verified token — `scope` → {@link ATTR_SCOPES}, `sub` →
 * {@link ATTR_USER_ID}, `azp` → {@link ATTR_CLIENT_ID}, the mapping AGENTS.md
 * tabulates — and the other two carry the entitlements the builtin rules
 * decide from. Either way the value is the deployment's to write and never the
 * caller's, so a collector that promotes caller-supplied data refuses to write
 * here rather than joining the deployment's own contributions.
 *
 * It matters because of how the maps combine: `AttributePipeline` **unions**
 * array-valued entries across collectors, so writing to one of these keys from
 * caller-supplied data does not overwrite the deployment's value — it extends
 * it, and nothing says so. A scalar key is no safer for being loud: two
 * disagreeing writers throw `AttributeConflictError`, which denies, so an
 * unguarded mapping trades a silent escalation for an unannounced outage.
 * Where the owning collector writes its key only *sometimes* — `packages/cedar`
 * omits `requestResourceId` for an id-less resource such as `"document"` —
 * there is no second writer to disagree with, and the caller's value stands
 * alone. See `AttributePipeline`'s merge doc comment.
 *
 * `RequestContextAttributeCollector` (builtins) is the one guard that consults
 * this today.
 */
export const RESERVED_ATTRIBUTE_KEYS: ReadonlySet<string> = reservedKeys;

/**
 * Reserves the attribute keys a package owns, so that a collector promoting
 * caller-supplied data refuses to write them.
 *
 * **Call it beside the `ATTR_*` constants, at module scope.** Reserving at
 * module load — rather than in a `Module.init`, or a collector factory — is
 * what makes the ordering hold without a rule anyone has to remember: a
 * composition can only name a package's collectors by importing the package,
 * an import runs the module body to completion before the importer's, and so
 * the keys are registered before any collector of any package can be
 * constructed. Reserving inside `init` would be later than that and would miss
 * a library consumer that never calls `createApp` at all.
 *
 * Reserving the same key twice under the same `owner` is a no-op, so a module
 * evaluated more than once (two versions of a package on the graph, a test
 * that re-imports it) is not a failure. Two *different* owners claiming one key
 * is refused: the keys are a vocabulary, and a key with two owners has no
 * answer to "who writes this, and may the caller?".
 *
 * The registry is this module's own state, so it is shared by everything that
 * resolves to the same copy of this package — which is the normal case, and
 * what the guard in builtins depends on. A dependency graph carrying two copies
 * of core would carry two registries, and a reservation made against one would
 * be invisible to a guard reading the other; dedupe core if a resolver ever
 * produces that.
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
 * @throws Error if `owner` or a key is not a non-empty string, or if any key is
 * already reserved by another package. Nothing is registered when it throws:
 * a half-applied batch would leave the calling package believing it holds a key
 * the registry never recorded.
 */
export function reserveAttributeKeys(request: AttributeKeyReservationRequest): void {
	const { owner, keys, reason } = request ?? {};
	if (typeof owner !== "string" || owner.length === 0) {
		throw new Error(
			`reserveAttributeKeys: owner must be a non-empty package name, got ${describe(owner)}`,
		);
	}

	// Validated and checked for conflicts in full before anything is written.
	const pending: AttributeKeyReservation[] = [];
	for (const key of keys ?? []) {
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
 * Who owns `key`, or `undefined` if nobody has reserved it.
 *
 * The owner is what lets a refusal name the package a key belongs to instead of
 * asserting it is core's — which stopped being true the moment a second package
 * reserved a vocabulary of its own.
 */
export function attributeKeyReservation(key: string): AttributeKeyReservation | undefined {
	return reservations.get(key);
}

/** Prefixes a suggested rename is drawn from, in order of preference. */
const SUGGESTION_PREFIXES = ["request", "caller", "context"] as const;

/**
 * A key like `key` that no package has reserved — the rename a refusal advises.
 *
 * Every candidate is checked against the registry, because the advice must not
 * walk into another package's vocabulary: `requestScopes` is a fine home for a
 * `scopes` field, and `request*` is also precisely what `packages/cedar` owns,
 * so a suggestion that only prefixed would eventually propose a name the very
 * next guard refuses. A prefix the key already carries is skipped rather than
 * doubled (`requestRequestResourceId` helps nobody).
 *
 * Terminates: the numbered fallback produces unboundedly many distinct
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
// Beside the constants, so that adding an `ATTR_*` above reserves it in the
// same edit — and, unlike the frozen set this replaces, a package that owns
// vocabulary core cannot see reserves it the same way.
reserveAttributeKeys({
	owner: CORE_ATTRIBUTE_KEY_OWNER,
	keys: [ATTR_SCOPES, ATTR_PERMISSIONS, ATTR_ROLES, ATTR_USER_ID, ATTR_CLIENT_ID],
	reason:
		"the engine's own vocabulary, written by the deployment — from the signature-verified token for scopes/userId/clientId, from configuration for roles/permissions",
});
