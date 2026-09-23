// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The key-resolver vocabulary: what a module registers to turn an
 * `oauth.jwt.algorithm` block into verification key material. It lived in core
 * until #170; it is the server's because it is token-credential plumbing, and
 * core's engine never touches a credential.
 *
 * Part of the authentication contract rather than of `jwt/` (#259): the
 * contract hands the key-resolver registry to every module
 * (`ServerModuleContext`) and to every authenticator factory
 * (`TokenAuthenticatorDependencies`), so a module that contributes a resolver,
 * or an authenticator that verifies JWTs of its own, has to name these types
 * without loading the built-in implementation. They carry no key library: the
 * key is `unknown`, and each implementation narrows it to what its library
 * takes.
 */

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
