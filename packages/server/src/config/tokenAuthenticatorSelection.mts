// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Which token authenticator a deployment runs (#219), read once for both
 * boundaries — see AGENTS.md, "Two-Boundary Config Validation".
 *
 * `oauth.authenticator` names an entry in the server's token-authenticator
 * registry, the way `oauth.jwt.algorithm` names a key resolver and
 * `attribute.collectors[].collector` names a collector. The built-in entry is
 * `"jwt"`, and it is the default, so every config written before this knob
 * existed reads exactly as it did. Whether the name is *registered* is the
 * registry's verdict at boot; what this function decides is the part both
 * boundaries can see: that the name is well-formed, and that the `jwt` block
 * is present whenever the built-in authenticator is the one selected — a
 * deployment running another authenticator has no use for it and must not be
 * made to write one.
 *
 * Dependency-free on purpose, like `checkJwksUri` and `resolveBound`:
 * `AppConfigSchema` imports it, so anything it reached back for would arrive
 * as a cycle.
 */

/** The name the built-in JWT authenticator is registered under, and the default selection. */
export const JWT_TOKEN_AUTHENTICATOR = "jwt";

/** The part of the `oauth` block this check reads. Loose on purpose: both boundaries hand it untrusted shapes. */
export interface TokenAuthenticatorSelectionInput {
	authenticator?: unknown;
	jwt?: unknown;
}

/**
 * The verdict. `key` is the `oauth.*` key the refusal is about, relative to
 * the block, for a boundary that reports issues by path; `message` already
 * names the key under `path`, so both boundaries refuse in the same words.
 */
export type TokenAuthenticatorSelectionCheck =
	| { ok: true; name: string }
	| { ok: false; key: "authenticator" | "jwt"; message: string };

/**
 * Resolves `oauth.authenticator`, defaulting an absent key to
 * {@link JWT_TOKEN_AUTHENTICATOR}, requires `oauth.jwt` when that is the
 * selection, and refuses it when it is not.
 *
 * A present-but-empty name is refused rather than defaulted: `${?ENV}`
 * substitution leaves an unset variable's key absent, so an empty string was
 * written (or rendered) on purpose, and reading it as "jwt" would silently
 * run a different authenticator from the one named.
 */
export function checkTokenAuthenticatorSelection(
	oauth: TokenAuthenticatorSelectionInput,
	path = "oauth",
): TokenAuthenticatorSelectionCheck {
	const { authenticator } = oauth;
	if (authenticator !== undefined && (typeof authenticator !== "string" || authenticator === "")) {
		return {
			ok: false,
			key: "authenticator",
			message: `${path}.authenticator must be a non-empty string`,
		};
	}
	const name = authenticator ?? JWT_TOKEN_AUTHENTICATOR;
	if (name === JWT_TOKEN_AUTHENTICATOR && oauth.jwt === undefined) {
		return {
			ok: false,
			key: "jwt",
			message: `${path}.jwt is required when ${path}.authenticator is "${JWT_TOKEN_AUTHENTICATOR}"`,
		};
	}
	if (name !== JWT_TOKEN_AUTHENTICATOR && oauth.jwt !== undefined) {
		// Nobody reads the block under another authenticator: the built-in
		// factory is not selected, and the selected one reads its own sub-block.
		// Carrying it unread would leave a leftover from switching authenticators
		// — or a mistake — in place, and a parsed type claiming a shape nothing
		// checked. Refused, pointing at the sub-block that is read.
		return {
			ok: false,
			key: "jwt",
			message: `${path}.jwt is not read when ${path}.authenticator is "${name}"; move its keys under ${path}.${name}`,
		};
	}
	return { ok: true, name };
}
