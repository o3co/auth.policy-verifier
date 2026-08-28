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

import type { ModuleContext, Registry } from "@o3co/auth.policy-verifier.core";

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
export interface ServerModuleContext extends ModuleContext {
	keyResolverRegistry: Registry<KeyResolverFactory>;
}
