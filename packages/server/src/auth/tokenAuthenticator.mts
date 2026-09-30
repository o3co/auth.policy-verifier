// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The token-authenticator port: what the verify router runs to turn an
 * `Authorization` header into a subject, and what a module registers to supply
 * one. The built-in bearer-JWT authenticator in `jwt/` implements it; a
 * deployment that authenticates another way implements it without loading
 * `jwt/` or jose.
 */

import type { EventLogger, Registry, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
import type { KeyResolverFactory } from "./keyResolver.mjs";

/**
 * Outcome of authenticating a caller. On failure the authenticator names the
 * machine-readable code and the caller-safe message; what HTTP status that
 * maps to is the route's concern, not the authenticator's.
 *
 * `missing_token`, `unsupported_scheme` and `invalid_token` are about the
 * credential: the caller has none this deployment accepts. The route answers
 * them `401`. `verification_unavailable` is about the authenticator: it could
 * not tell whether the credential is good — the keys it needs could not be
 * fetched, say — so the caller's credential may be fine, and the route
 * answers `503`. Either way nothing is allowed.
 *
 * `subject` is core's neutral `SubjectAttributes` bag, and the authenticator
 * is the one edge that populates it — the built-in one spreads the claims of
 * the JWT it accepted into it (signature-verified unless `oauth.jwt.mode` is
 * `"insecure-decode"`). `credential` is the raw credential, carried beside the
 * bag rather than in it: the route decides whether a collector ever sees it.
 */
export type AuthenticationResult =
	| { ok: true; subject: SubjectAttributes; credential: string }
	| {
			ok: false;
			code: "missing_token" | "unsupported_scheme" | "invalid_token" | "verification_unavailable";
			message: string;
	  };

/**
 * Authenticates one `Authorization` header value into the subject attributes
 * it accepts.
 */
export interface TokenAuthenticator {
	authenticate(authorizationHeader: string | undefined): Promise<AuthenticationResult>;
}

/**
 * What the host hands a {@link TokenAuthenticatorFactory} besides its config:
 * the failure-event sink the built-in authenticator logs to, and the key
 * resolvers the modules registered — so an authenticator that verifies JWTs
 * of its own (an IdP's session token, say) reuses `oauth.jwt.algorithm`'s
 * plumbing rather than re-implementing it.
 */
export interface TokenAuthenticatorDependencies {
	logger: EventLogger;
	keyResolverRegistry: Registry<KeyResolverFactory>;
}

/**
 * Builds the authenticator `oauth.authenticator` selects. Receives the
 * whole `oauth` block — the built-in one reads `oauth.jwt`, and a factory
 * registered under another name reads whatever sub-block it documents for
 * itself — and returns the {@link TokenAuthenticator} the verify router runs,
 * so what it produces feeds the same subject bag. Async because building one
 * may fetch keys or open a client.
 */
export type TokenAuthenticatorFactory = (
	// biome-ignore lint/suspicious/noExplicitAny: authenticator factories accept their own config shapes
	oauth: any,
	deps: TokenAuthenticatorDependencies,
) => Promise<TokenAuthenticator>;
