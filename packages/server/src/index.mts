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
	DEFAULT_CLOCK_TOLERANCE_SECONDS,
	DEFAULT_HOSTNAME,
	DEFAULT_MAX_BATCH_SIZE,
	DEFAULT_MAX_TOKEN_AGE_SECONDS,
	MAX_CLOCK_TOLERANCE_SECONDS,
	MAX_PREVIOUS_SECRETS,
	MIN_SECRET_ENTROPY_BYTES,
} from "./config/defaults.mjs";
// The HS256 entropy floor's measurement (#114), exported so a consumer that
// accepts its own operator secrets — a custom key resolver, a composition root
// building a JWT config by hand — applies the identical reading rather than a
// second opinion about what a 32-character hex string is worth.
export { describeWeakSecret, measureSecretEntropyBytes } from "./config/secretEntropy.mjs";
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
	checkHs256Rotation,
	checkJwksUri,
	type DecodingJwtConfig,
	EdDSAKeyResolverFactory,
	ES256KeyResolverFactory,
	HS256KeyResolverFactory,
	type Hs256PreviousSecret,
	type Hs256Rotation,
	type Hs256RotationCheck,
	type Hs256RotationConfig,
	type Hs256RotationIssue,
	type JwksFetchBounds,
	type JwksFetchConfig,
	type JwksUriCheck,
	type JwtConfigErrorContext,
	type JwtTimeClaimBounds,
	type JwtTimeClaimConfig,
	parseHs256Rotation,
	parseJwksUri,
	RS256KeyResolverFactory,
	resolveJwksFetchBounds,
	resolveJwtTimeClaimBounds,
	type UncheckedJwtConfig,
	type VerifyingJwtConfig,
	type VerifyRouterJwtConfig,
} from "./jwt/index.mjs";
export { isLoopbackBindAddress, isLoopbackHost } from "./net/loopback.mjs";
export {
	DECISION_EVENT,
	type DecisionEventInput,
	type DenyingGroup,
	decisionEvent,
	type NamedRule,
} from "./observability/decisionEvent.mjs";
export {
	type CreateMetricsOptions,
	createMetrics,
	DEFAULT_METRICS_PATH,
	type DecisionMetrics,
	type DecisionObservation,
	MAX_DENY_CODE_LABELS,
	type Metrics,
} from "./observability/metrics.mjs";
export { createVerifyRouter, type VerifyRouterConfig } from "./routes/verify.mjs";
