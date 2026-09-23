// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The context this server initializes its modules with: core's module context
 * plus the two authentication registries a module may contribute to — key
 * resolvers and token authenticators.
 */

import type { ModuleContext, Registry } from "@o3co/auth.policy-verifier.core";
import type { KeyResolverFactory } from "./keyResolver.mjs";
import type { TokenAuthenticatorFactory } from "./tokenAuthenticator.mjs";

/**
 * Core's base {@link ModuleContext} plus the JWT key-resolver registry and the
 * token-authenticator registry. A module that registers into either is a
 * `Module<ServerModuleContext>` and can only be initialized by a host
 * supplying this shape; a plain `Module` neither sees nor needs the extra
 * registries and runs here unchanged.
 */
export interface ServerModuleContext extends ModuleContext {
	keyResolverRegistry: Registry<KeyResolverFactory>;
	/**
	 * Token authenticators by name (#219). `createApp` registers the built-in
	 * `"jwt"` entry before any module runs; a module contributes an alternative
	 * under its own name, and `oauth.authenticator` selects one.
	 */
	tokenAuthenticatorRegistry: Registry<TokenAuthenticatorFactory>;
}
