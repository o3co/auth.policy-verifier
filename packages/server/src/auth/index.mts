// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The authentication contract, re-exported for the package index: types only,
 * so importing it loads nothing.
 */

export type { KeyResolver, KeyResolverFactory } from "./keyResolver.mjs";
export type { ServerModuleContext } from "./serverModuleContext.mjs";
export type {
	AuthenticationResult,
	TokenAuthenticator,
	TokenAuthenticatorDependencies,
	TokenAuthenticatorFactory,
} from "./tokenAuthenticator.mjs";
