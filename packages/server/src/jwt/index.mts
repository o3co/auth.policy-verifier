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
	checkHs256Rotation,
	type Hs256PreviousSecret,
	type Hs256Rotation,
	type Hs256RotationCheck,
	type Hs256RotationConfig,
	type Hs256RotationIssue,
	parseHs256Rotation,
} from "./hs256Rotation.mjs";
export {
	checkJwksUri,
	type JwksFetchBounds,
	type JwksFetchConfig,
	type JwksUriCheck,
	parseJwksUri,
	resolveJwksFetchBounds,
} from "./jwks.mjs";
export {
	type AssertedJwtConfig,
	type AuthenticationResult,
	assertVerifyRouterJwtConfig,
	createTokenAuthenticator,
	type DecodingJwtConfig,
	type JwtConfigErrorContext,
	type JwtTimeClaimBounds,
	type JwtTimeClaimConfig,
	resolveJwtTimeClaimBounds,
	type TokenAuthenticator,
	type UncheckedJwtConfig,
	type VerifyingJwtConfig,
	type VerifyRouterJwtConfig,
} from "./tokenAuthenticator.mjs";
