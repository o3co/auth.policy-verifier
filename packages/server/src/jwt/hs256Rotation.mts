// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * HS256 signing-secret rotation (#112): the config shape a deployment writes to
 * hold a retired secret alongside the current one, and the checks that shape
 * must pass before any of it becomes key material.
 *
 * Why this exists at all: with exactly one secret, rotating means the provider
 * starts signing with a new value and every token minted under the old one is
 * refused from that instant — the two services have to restart in lockstep, and
 * everything in flight is denied in between. That is a coordinated outage in
 * the algorithm this stack ships as its default.
 *
 * The contract is auth.provider's, not a new one. That project rotates through
 * `previousSecrets` — `kid` + `secret` + `expiresAt` per entry, current secret
 * named by its own `kid` — in `packages/core/src/keys/factory.mts`. The wire
 * shape here is the same, so an operator rotating the pair writes the same
 * three fields on both sides and moves the same pair of values.
 *
 * Deliberately dependency-free, like `jwt/jwks.mts` next to it: `AppConfigSchema`
 * imports it so a malformed rotation block fails at config-parse time (at boot,
 * where an operator sees it) rather than at the first request, and config-only
 * consumers of the schema must not pull jose or express in behind it. The
 * `KeyResolverFactory` re-checks at construction for hand-built configs that
 * never went through the schema — the same division of labor as
 * `checkJwksUri` / `parseJwksUri`.
 */

import { MAX_PREVIOUS_SECRETS } from "../config/defaults.mjs";

/**
 * One retired secret and the window it stays a verification key for.
 *
 * `expiresAt` is an ISO 8601 timestamp rather than a duration because it states
 * a moment both services can be pointed at: the operator sets the same value on
 * the provider, and the overlap window then closes on its own. It is read at
 * verification time, not at boot — a long-running verifier must see the window
 * end without a restart.
 */
export interface Hs256PreviousSecret {
	kid: string;
	secret: string;
	expiresAt: string;
}

/*
 * A note on the name, which is auth.provider's and is kept on purpose: on a
 * verifier this list is "every secret accepted besides the current one", not
 * strictly the retired ones. An outage-free rotation needs the verifier to span
 * the cutover from both sides, so the operator stages the INCOMING secret here
 * before the provider has ever signed with it, and only afterwards demotes the
 * outgoing one into the same list. Both directions are the same mechanism —
 * accept a secret that is not the one currently named by `kid` — and giving the
 * verifier a second, differently-named field for the first half would make the
 * two sides of one rotation look like two unrelated features.
 */

/**
 * The rotation-carrying subset of an `oauth.jwt` block, deliberately loose:
 * {@link checkHs256Rotation} exists precisely for configs whose static types
 * cannot be trusted — `createApp` accepts hand-built objects, and a JavaScript
 * caller can put anything at `previousSecrets`.
 */
export interface Hs256RotationConfig {
	secret?: string;
	/**
	 * Names the secret the issuer currently signs with. Optional, and the
	 * absent case is the pre-#112 shape: no `kid` configured means the header is
	 * not consulted at all. Required once `previousSecrets` is non-empty, since
	 * nothing else tells the current secret apart from the retired ones.
	 */
	kid?: string;
	previousSecrets?: unknown;
}

/** One rejected field, at the path inside the JWT block where it was written. */
export interface Hs256RotationIssue {
	/** Path relative to the `oauth.jwt` block, e.g. `["previousSecrets", 0, "kid"]`. */
	path: (string | number)[];
	/** Operator-facing reason, naming the field the same way the path does. */
	message: string;
}

/** The narrowed rotation config, once every check has passed. */
export interface Hs256Rotation {
	kid?: string;
	previousSecrets: Hs256PreviousSecret[];
}

/**
 * Outcome of {@link checkHs256Rotation}: the narrowed config, or every reason
 * it was refused. A result rather than a throw because the schema reports these
 * as zod issues among others, at the paths the operator wrote — and all of them
 * at once, so a rotation block with two mistakes takes one round trip to fix.
 */
export type Hs256RotationCheck =
	| ({ ok: true } & Hs256Rotation)
	| { ok: false; issues: Hs256RotationIssue[] };

/** True for a value that is a usable non-empty string. */
function isNonEmptyString(value: unknown): value is string {
	return typeof value === "string" && value.length > 0;
}

/**
 * Validates one `previousSecrets` entry into the collector, returning the
 * narrowed entry or `undefined` when it contributed an issue instead.
 *
 * Note what is deliberately NOT checked here: the entropy of `secret`. A retired
 * secret is a live verification key for the whole overlap window, so it carries
 * exactly the forgery risk the current one does and belongs behind exactly the
 * same floor — which is why that floor is one check over `oauth.jwt.secret` and
 * every entry of this list together (tracked as #114), and not a check that
 * lands here alone and leaves the current secret the laxer of the two.
 */
function checkEntry(
	entry: unknown,
	index: number,
	issues: Hs256RotationIssue[],
): Hs256PreviousSecret | undefined {
	const at = (field?: string): (string | number)[] =>
		field === undefined ? ["previousSecrets", index] : ["previousSecrets", index, field];
	const label = `previousSecrets[${index}]`;

	if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
		issues.push({
			path: at(),
			message: `${label} must be an object with kid, secret and expiresAt`,
		});
		return undefined;
	}
	const raw = entry as Record<string, unknown>;
	let ok = true;
	for (const field of ["kid", "secret"] as const) {
		if (!isNonEmptyString(raw[field])) {
			issues.push({ path: at(field), message: `${label}.${field} must be a non-empty string` });
			ok = false;
		}
	}
	if (!isNonEmptyString(raw.expiresAt)) {
		issues.push({
			path: at("expiresAt"),
			message: `${label}.expiresAt must be a non-empty ISO 8601 timestamp`,
		});
		ok = false;
	} else if (Number.isNaN(Date.parse(raw.expiresAt))) {
		// The value is the operator's own config, not key material, so echoing it
		// is what makes a typo obvious.
		issues.push({
			path: at("expiresAt"),
			message: `${label}.expiresAt is not a valid timestamp: ${JSON.stringify(raw.expiresAt)}`,
		});
		ok = false;
	}
	if (!ok) {
		return undefined;
	}
	return {
		kid: raw.kid as string,
		secret: raw.secret as string,
		expiresAt: raw.expiresAt as string,
	};
}

/**
 * Applies the rotation contract to an `oauth.jwt` block.
 *
 * An *absent* `previousSecrets` means "no rotation configured": a deployment
 * that has never rotated writes nothing, and an operator closing a window
 * deletes the block rather than having to remember an empty-list anchor. `[]`
 * says the same thing explicitly. Anything else that is not a list — `null`
 * included — is refused rather than ignored: silently dropping it would take
 * the verifier back to holding one secret while the config visibly says
 * otherwise, which is the failure this closes.
 *
 * `null` is deliberately NOT a second spelling for absent, and this is the one
 * place the port diverges from auth.provider's `narrowPreviousSecretsArray`
 * (which reads it as an explicit opt-out). Three reasons, none of them about
 * the wire contract — the `{ kid, secret, expiresAt }` triple and the
 * kid-overlap semantics are ported unchanged:
 *
 * 1. `AppConfigSchema` types the field `z.array(...).optional()`, which rejects
 *    `null` before this function is ever reached. Accepting it here would give
 *    a hand-built config a different answer than a parsed one — the exact
 *    invariant this guard exists to hold (see `resolveJwksFetchBounds`).
 * 2. No other optional key in the `oauth.jwt` block has a `null` spelling:
 *    `secret`, `kid`, `jwksUri`, `publicKey` and `publicKeyPath` are all
 *    absent-or-a-value. One field with a private third spelling is a trap.
 * 3. A `null` that reached a config was almost certainly produced, not
 *    written — an unrendered template value, a missing env var, a JSON
 *    serializer emitting the key anyway. Reading that as "nothing is being
 *    rotated" boots a verifier that will deny every token signed with the
 *    retired secret the moment the provider cuts over, which is #112 again.
 *    Failing at boot names the key instead.
 */
export function checkHs256Rotation(config: Hs256RotationConfig): Hs256RotationCheck {
	const issues: Hs256RotationIssue[] = [];
	const { kid } = config;

	if (kid !== undefined && !isNonEmptyString(kid)) {
		issues.push({ path: ["kid"], message: "kid must be a non-empty string" });
	}

	const raw = config.previousSecrets;
	const previousSecrets: Hs256PreviousSecret[] = [];
	if (raw !== undefined) {
		if (!Array.isArray(raw)) {
			issues.push({
				path: ["previousSecrets"],
				message:
					"previousSecrets must be an array of { kid, secret, expiresAt } entries, " +
					"or omitted entirely when nothing is being rotated — null is not a spelling " +
					"for omitted",
			});
		} else if (raw.length > MAX_PREVIOUS_SECRETS) {
			// Checked before the entries, and reported alone: the cap is about how
			// much work one verification may cost, so a list that exceeds it is
			// refused whatever the entries look like.
			issues.push({
				path: ["previousSecrets"],
				message:
					`previousSecrets accepts at most ${MAX_PREVIOUS_SECRETS} entries, got ${raw.length} — ` +
					"a token carrying no kid is tried against every configured secret, so the list " +
					"length is the per-verification work bound",
			});
		} else {
			const seen = new Set<string>(isNonEmptyString(kid) ? [kid] : []);
			for (const [index, entry] of raw.entries()) {
				const checked = checkEntry(entry, index, issues);
				if (checked === undefined) {
					continue;
				}
				if (seen.has(checked.kid)) {
					// Two secrets under one kid make kid lookup ambiguous, and the
					// overlap window of whichever loses is silently unenforced.
					issues.push({
						path: ["previousSecrets", index, "kid"],
						message: `previousSecrets[${index}].kid duplicates another configured kid: ${JSON.stringify(checked.kid)}`,
					});
					continue;
				}
				seen.add(checked.kid);
				previousSecrets.push(checked);
			}
		}
	}

	if (previousSecrets.length > 0 && !isNonEmptyString(kid)) {
		issues.push({
			path: ["kid"],
			message:
				"kid is required when previousSecrets is configured — it names the secret the " +
				"issuer signs with today, which is what tells it apart from the retired ones",
		});
	}

	if (issues.length > 0) {
		return { ok: false, issues };
	}
	return kid === undefined ? { ok: true, previousSecrets } : { ok: true, kid, previousSecrets };
}

/**
 * {@link checkHs256Rotation} for callers that cannot collect issues — throws the
 * first refusal with the same wording the schema reports, prefixed with the
 * config path so both boundaries name the key the operator actually wrote.
 *
 * @param path Config path of the JWT block at the calling boundary. `createApp`
 * hands the `oauth.jwt` block to the `KeyResolverFactory`, so that is the
 * default; a custom factory reached by another path passes its own.
 */
export function parseHs256Rotation(config: Hs256RotationConfig, path = "oauth.jwt"): Hs256Rotation {
	const checked = checkHs256Rotation(config);
	if (!checked.ok) {
		const [first] = checked.issues;
		throw new Error(`${path}.${first?.message ?? "previousSecrets is invalid"}`);
	}
	const { ok: _ok, ...rotation } = checked;
	return rotation;
}
