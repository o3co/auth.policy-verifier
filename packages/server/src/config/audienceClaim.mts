// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Where the audience is read from, and whether the `typ` header is pinned
 * (#219) — the two knobs that let the built-in JWT path accept an external
 * IdP's token without a custom authenticator. The comparison itself is the
 * authenticator's (`audienceMatches` in `jwt/tokenAuthenticator.mts`).
 *
 * RFC 9068 §4 has a resource server check `aud`. Not every issuer puts the
 * binding there: a Clerk session token carries no `aud` at all and binds the
 * origin in `azp`; a Cognito access token carries `client_id` where its
 * id_token carries `aud`. `audienceClaim` moves the check to the named claim;
 * it never removes it, and `audience` stays required.
 *
 * Dependency-free on purpose, like `checkJwksUri`: `AppConfigSchema` imports
 * it, and the built-in authenticator in `jwt/` reads the same verdict through
 * it — see AGENTS.md, "Two-Boundary Config Validation". It lives in `config/`
 * so that the dependency runs one way, `jwt/` → `config/` (#260).
 */

/** The claim RFC 9068 §4 names, and the default `audienceClaim`. */
export const DEFAULT_AUDIENCE_CLAIM = "aud";

/**
 * The one `tokenType` that pins nothing: any `typ` header, or none. jose
 * refuses a token with no `typ` under any pinned value, and some issuers
 * (Cognito) emit none, so the opt-out has to be a value an operator writes on
 * purpose. `*` is not a media-type name, so it can never collide with a real
 * `typ`. With it set, the audience is the only thing telling an access token
 * from an id_token signed with the same key — pair it with a precise
 * `audience`, and an `audienceClaim` the other kind does not carry.
 */
export const UNPINNED_TOKEN_TYPE = "*";

/** The verdict on an `audienceClaim` value: the claim to read, or why the value is refused. */
export type AudienceClaimCheck = { ok: true; claim: string } | { ok: false; message: string };

/**
 * Resolves `audienceClaim`: absent means {@link DEFAULT_AUDIENCE_CLAIM}, a
 * non-empty string names the claim, anything else is refused. The message
 * names the key relative to the `jwt` block, the way the schema's other
 * `jwt.*` issues do; the runtime guard prefixes its own path.
 */
export function checkAudienceClaim(value: unknown): AudienceClaimCheck {
	if (value === undefined) return { ok: true, claim: DEFAULT_AUDIENCE_CLAIM };
	if (typeof value !== "string" || value === "") {
		return { ok: false, message: "audienceClaim must be a non-empty string" };
	}
	return { ok: true, claim: value };
}
