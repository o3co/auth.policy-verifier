// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

export { type CreateAppOptions, createApp } from "./app.mjs";
export {
	type AppConfig,
	AppConfigSchema,
	JWT_MODE_MIGRATION_MESSAGE,
} from "./config/application.schema.mjs";
export {
	type AssertedJwtConfig,
	assertVerifyRouterJwtConfig,
	builtinKeyResolversModule,
	checkJwksUri,
	type DecodingJwtConfig,
	EdDSAKeyResolverFactory,
	ES256KeyResolverFactory,
	HS256KeyResolverFactory,
	type JwksFetchBounds,
	type JwksFetchConfig,
	type JwksUriCheck,
	type JwtConfigErrorContext,
	parseJwksUri,
	RS256KeyResolverFactory,
	resolveJwksFetchBounds,
	type UncheckedJwtConfig,
	type VerifyingJwtConfig,
	type VerifyRouterJwtConfig,
} from "./jwt/index.mjs";
export { createVerifyRouter, type VerifyRouterConfig } from "./routes/verify.mjs";
