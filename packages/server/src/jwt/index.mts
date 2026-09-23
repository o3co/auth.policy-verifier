// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

export {
	builtinKeyResolversModule,
	EdDSAKeyResolverFactory,
	ES256KeyResolverFactory,
	HS256KeyResolverFactory,
	RS256KeyResolverFactory,
} from "./builtinKeyResolversModule.mjs";
export {
	JWT_TOKEN_AUTHENTICATOR,
	JwtTokenAuthenticatorFactory,
} from "./jwtTokenAuthenticatorFactory.mjs";
export {
	type AssertedJwtConfig,
	assertVerifyRouterJwtConfig,
	audienceMatches,
	createTokenAuthenticator,
	type DecodingJwtConfig,
	type JwtConfigErrorContext,
	type JwtTimeClaimBounds,
	type JwtTimeClaimConfig,
	resolveJwtTimeClaimBounds,
	type UncheckedJwtConfig,
	type VerifyingJwtConfig,
	type VerifyRouterJwtConfig,
} from "./tokenAuthenticator.mjs";
