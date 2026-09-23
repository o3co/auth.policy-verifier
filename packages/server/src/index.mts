// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

export { type CreateAppOptions, createApp } from "./app.mjs";
export type {
	AuthenticationResult,
	KeyResolver,
	KeyResolverFactory,
	ServerModuleContext,
	TokenAuthenticator,
	TokenAuthenticatorDependencies,
	TokenAuthenticatorFactory,
} from "./auth/index.mjs";
export {
	type AppConfig,
	AppConfigSchema,
	JWT_MODE_MIGRATION_MESSAGE,
} from "./config/application.schema.mjs";
export {
	type AudienceClaimCheck,
	checkAudienceClaim,
	DEFAULT_AUDIENCE_CLAIM,
	UNPINNED_TOKEN_TYPE,
} from "./config/audienceClaim.mjs";
export {
	CALLER_AUTH_REQUIRED,
	DEFAULT_BATCH_CONCURRENCY,
	DEFAULT_CALLER_AUTH_HEADER,
	DEFAULT_CLOCK_TOLERANCE_SECONDS,
	DEFAULT_HOSTNAME,
	DEFAULT_HTTP_PORT,
	DEFAULT_MAX_BATCH_SIZE,
	DEFAULT_MAX_TOKEN_AGE_SECONDS,
	MAX_CLOCK_TOLERANCE_SECONDS,
	MAX_PREVIOUS_SECRETS,
	MAX_TCP_PORT,
	MIN_SECRET_ENTROPY_BYTES,
} from "./config/defaults.mjs";
export {
	checkHs256Rotation,
	type Hs256PreviousSecret,
	type Hs256Rotation,
	type Hs256RotationCheck,
	type Hs256RotationConfig,
	type Hs256RotationIssue,
	parseHs256Rotation,
} from "./config/hs256Rotation.mjs";
export {
	checkJwksUri,
	type JwksFetchBounds,
	type JwksFetchConfig,
	type JwksUriCheck,
	parseJwksUri,
	resolveJwksFetchBounds,
} from "./config/jwks.mjs";
// The HS256 entropy floor's measurement (#114), exported so a consumer that
// accepts its own operator secrets — a custom key resolver, a composition root
// building a JWT config by hand — applies the identical reading rather than a
// second opinion about what a 32-character hex string is worth.
export { describeWeakSecret, measureSecretEntropyBytes } from "./config/secretEntropy.mjs";
export {
	checkTokenAuthenticatorSelection,
	type TokenAuthenticatorSelectionCheck,
	type TokenAuthenticatorSelectionInput,
} from "./config/tokenAuthenticatorSelection.mjs";
export {
	type CallerAuthConfig,
	type CallerAuthErrorContext,
	createCallerAuthMiddleware,
	resolveCallerAuth,
} from "./http/callerAuth.mjs";
export {
	acceptRequestId,
	MAX_REQUEST_ID_LENGTH,
	REQUEST_ID_HEADER,
} from "./http/requestId.mjs";
export {
	type AssertedJwtConfig,
	assertVerifyRouterJwtConfig,
	audienceMatches,
	builtinKeyResolversModule,
	createTokenAuthenticator,
	type DecodingJwtConfig,
	EdDSAKeyResolverFactory,
	ES256KeyResolverFactory,
	HS256KeyResolverFactory,
	JWT_TOKEN_AUTHENTICATOR,
	type JwtConfigErrorContext,
	type JwtTimeClaimBounds,
	type JwtTimeClaimConfig,
	JwtTokenAuthenticatorFactory,
	RS256KeyResolverFactory,
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
export type {
	CollectorFailureObservation,
	DecisionMetrics,
	DecisionObservation,
} from "./observability/decisionMetrics.mjs";
export {
	type ClassifiedFailure,
	type CollectorFailureCategory,
	FAILURE_CATEGORIES,
	type FailureCategory,
} from "./observability/failure.mjs";
export {
	type CreateMetricsOptions,
	createMetrics,
	DEFAULT_METRICS_PATH,
	MAX_COLLECTOR_LABELS,
	MAX_DENY_CODE_LABELS,
	type Metrics,
} from "./observability/metrics.mjs";
export { createVerifyRouter, type VerifyRouterConfig } from "./routes/verify.mjs";
