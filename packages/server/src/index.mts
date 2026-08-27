// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

export { type CreateAppOptions, createApp } from "./app.mjs";
export {
	type AppConfig,
	AppConfigSchema,
	JWT_MODE_MIGRATION_MESSAGE,
} from "./config/application.schema.mjs";
export {
	CALLER_AUTH_REQUIRED,
	DEFAULT_CALLER_AUTH_HEADER,
	DEFAULT_HOSTNAME,
	DEFAULT_MAX_BATCH_SIZE,
} from "./config/defaults.mjs";
export {
	type CallerAuthConfig,
	type CallerAuthErrorContext,
	createCallerAuthMiddleware,
	resolveCallerAuth,
} from "./http/callerAuth.mjs";
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
export { isLoopbackBindAddress, isLoopbackHost } from "./net/loopback.mjs";
export { createVerifyRouter, type VerifyRouterConfig } from "./routes/verify.mjs";
