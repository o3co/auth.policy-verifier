// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The key-resolver vocabulary, and the module context that carries its
 * registry. Both lived in core until #170; they are the server's because they
 * are token-credential plumbing — every consumer of a `KeyResolver` is on the
 * JWT authentication path, and core's engine never touches a credential. A
 * host that authenticates some other way runs the same core with no key
 * resolver anywhere in sight.
 */

import type { EventLogger, ModuleContext, Registry } from "@o3co/auth.policy-verifier.core";
import type { TokenAuthenticator } from "./tokenAuthenticator.mjs";

/**
 * Abstract JWT key resolver. The concrete `key` type is determined by the
 * consuming JWT library (e.g. jose's `KeyObject | CryptoKey | Uint8Array | JWTVerifyGetKey`).
 * Kept `unknown` so new algorithms can be introduced without touching this type.
 */
export interface KeyResolver {
	key: unknown;
	algorithms: string[];
}

/**
 * Factory that produces a KeyResolver for a given JWT algorithm.
 * Async because some resolvers import PEM files or fetch JWKS metadata.
 */
// biome-ignore lint/suspicious/noExplicitAny: key resolver factories accept algorithm-specific config shapes
export type KeyResolverFactory = (config: any) => Promise<KeyResolver>;

/**
 * The context this server initializes its modules with: core's base
 * {@link ModuleContext} plus the JWT key-resolver registry. A module that
 * registers key resolvers is a `Module<ServerModuleContext>` and can only be
 * initialized by a host supplying this shape; a plain `Module` neither sees
 * nor needs the extra registry and runs here unchanged.
 */
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
 * Builds the authenticator `oauth.authenticator` selects (#219). Receives the
 * whole `oauth` block — the built-in one reads `oauth.jwt`, and a factory
 * registered under another name reads whatever sub-block it documents for
 * itself — and returns the same {@link TokenAuthenticator} the verify router
 * has always run, so what it produces feeds the same subject bag. Async
 * because building one may fetch keys or open a client.
 */
export type TokenAuthenticatorFactory = (
	// biome-ignore lint/suspicious/noExplicitAny: authenticator factories accept their own config shapes
	oauth: any,
	deps: TokenAuthenticatorDependencies,
) => Promise<TokenAuthenticator>;

export interface ServerModuleContext extends ModuleContext {
	keyResolverRegistry: Registry<KeyResolverFactory>;
	/**
	 * Token authenticators by name (#219). `createApp` registers the built-in
	 * `"jwt"` entry before any module runs; a module contributes an alternative
	 * under its own name, and `oauth.authenticator` selects one.
	 */
	tokenAuthenticatorRegistry: Registry<TokenAuthenticatorFactory>;
}
