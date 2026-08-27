// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type AttributeCollectorFactory,
	AttributePipeline,
	createConsoleLogger,
	type KeyResolverFactory,
	type Logger,
	type Module,
	type PathResolver,
	Registry,
	type ResourceParserFactory,
	type RuleCollectorFactory,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import { createHealthcheckRouter } from "@o3co/auth.utils/express";
import express from "express";
import { type AppConfig, JWT_MODE_MIGRATION_MESSAGE } from "./config/application.schema.mjs";
import { CALLER_AUTH_REQUIRED } from "./config/defaults.mjs";
import { createCallerAuthMiddleware, resolveCallerAuth } from "./http/callerAuth.mjs";
import {
	assertVerifyRouterJwtConfig,
	resolveJwtTimeClaimBounds,
	type VerifyRouterJwtConfig,
} from "./jwt/tokenAuthenticator.mjs";
import { isLoopbackBindAddress } from "./net/loopback.mjs";
import { createVerifyRouter } from "./routes/verify.mjs";

/** Options accepted by `createApp`. */
export interface CreateAppOptions {
	pathResolver: PathResolver;
	config: AppConfig;
	modules: Module[];
	/**
	 * Structured logger for boot-time warnings and the verify router's failure
	 * events. Pino-compatible (a pino instance satisfies it without an adapter).
	 * Defaults to the console-backed logger at `config.logging.level`, so
	 * failures are never silent even when nothing is wired.
	 */
	logger?: Logger;
}

/**
 * Asserts that a config block a hand-built config supplies is actually an
 * object, so the checks that follow can index into it. `createApp` accepts
 * config objects that never went through `AppConfigSchema`, and a JavaScript
 * caller can put anything at a given path; without this the first `in` test or
 * object spread throws a bare `TypeError` naming neither the boundary nor the
 * path the operator wrote. Arrays are rejected too: indexable, but never a
 * valid config block.
 */
function assertConfigObject(value: unknown, path: string): asserts value is object {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error(
			`createApp: ${path} must be a config object, got ${value === null ? "null" : Array.isArray(value) ? "array" : typeof value}`,
		);
	}
}

/**
 * Builds the Express app with registries initialized by the supplied modules.
 *
 * Flow: (1) create registries, (2) run `mod.init` sequentially so later modules
 * can see earlier ones' registrations, (3) resolve concrete collectors /
 * resource parser / key resolver from config, (4) mount the healthcheck, the
 * optional caller-auth gate and the `/verify` router under the configured path
 * prefix.
 *
 * `config.http.callerAuth.token` authenticates the *calling service* before any
 * decision work runs (#108). It is optional in this release; the healthcheck is
 * never gated. See `CALLER_AUTH_REQUIRED` in `config/defaults` for the one-line
 * change that makes it mandatory.
 *
 * `config.oauth.jwt.mode = "insecure-decode"` disables signature verification
 * and only decodes the token (the time claims are still enforced in full —
 * `exp` and `iat` required, `nbf` honoured, `maxTokenAgeSeconds` applied). It is
 * test-only; the mode string itself is the explicit consent (#134) — an
 * accidental env-var flip can produce a stray boolean but never that literal
 * string, which preserves the intent of #106's double opt-in in one knob.
 * Booting in that mode is logged at error level (#106).
 */
export async function createApp(options: CreateAppOptions): Promise<express.Express> {
	const { pathResolver, config, modules } = options;
	const logger = options.logger ?? createConsoleLogger({}, { level: config.logging.level });

	// 1. Create registries (factories, not instances)
	const attributeCollectorRegistry = new Registry<AttributeCollectorFactory>();
	const ruleCollectorRegistry = new Registry<RuleCollectorFactory>();
	const resourceParserRegistry = new Registry<ResourceParserFactory>();
	const keyResolverRegistry = new Registry<KeyResolverFactory>();

	// 2. Initialize modules — each registers factory functions
	const context = {
		pathResolver,
		config: config as unknown as Record<string, unknown>,
		attributeCollectorRegistry,
		ruleCollectorRegistry,
		resourceParserRegistry,
		keyResolverRegistry,
	};

	for (const mod of modules) {
		await mod.init(context);
	}

	// 3. Resolve attribute collectors from config — call factory with config entry
	const attributeCollectors = config.attribute.collectors.map((entry) => {
		const factory = attributeCollectorRegistry.get(entry.collector);
		return factory(entry);
	});

	// 4. Resolve rule collectors from config — call factory with config entry.
	// A pipeline with no rule collector can never authorize anything: every request
	// would collect an empty rule set and be denied. Fail at boot rather than serve
	// a verifier that only ever says no.
	if (config.rule.collectors.length === 0) {
		throw new Error("createApp: at least one rule collector must be configured (rule.collectors)");
	}
	const ruleCollectors = config.rule.collectors.map((entry) => {
		const factory = ruleCollectorRegistry.get(entry.collector);
		return factory(entry);
	});

	// 5. Resolve resource parser from config
	const resourceParserFactory = resourceParserRegistry.get(config.resource.parser);
	const resourceParser = resourceParserFactory(config.resource);

	// 6. Map the wire `oauth.jwt.mode` onto the router's internal discriminated
	// union (#134). AppConfigSchema already enforces the wire invariants (the
	// mode enum, iss/aud/typ presence, rejection of the removed keys) for
	// schema-validated configs; everything is re-checked here because createApp
	// also accepts hand-built config objects that never went through the schema
	// (#106) — with this boundary's field paths, so the operator is pointed at
	// the oauth.jwt.* key they actually wrote.
	//
	// Shape first: a hand-built config can carry anything at these paths, and
	// the key checks below reach into the block with `in` and object spread,
	// which throw a bare TypeError on a primitive. Report a malformed block like
	// every other boundary failure instead of leaking that TypeError.
	assertConfigObject(config.oauth, "oauth");
	assertConfigObject(config.oauth.jwt, "oauth.jwt");
	const jwtWire = config.oauth.jwt;
	for (const staleKey of ["validate", "allowInsecureDecode"] as const) {
		if (staleKey in jwtWire) {
			// A pre-#134 config must not be silently reinterpreted: a defaulted
			// mode would mean verify even where the operator had opted into
			// decode-only. Fail with the same migration message the schema emits.
			throw new Error(`createApp: ${JWT_MODE_MIGRATION_MESSAGE}`);
		}
	}
	// Hand-built configs may omit `mode`; they get the schema's default (verify).
	const mode: unknown = (jwtWire as { mode?: unknown }).mode ?? "verify";
	// Ahead of the mode split, because the token lifetime bounds (#110) apply in
	// both modes — the decode path restates them by hand rather than skipping
	// them — and resolving here is what lets a bad value be reported against the
	// `oauth.jwt.*` key the operator actually wrote.
	const timeClaims = resolveJwtTimeClaimBounds(jwtWire, "oauth.jwt");
	const bounds = {
		maxTokenAgeSeconds: timeClaims.maxTokenAge,
		clockToleranceSeconds: timeClaims.clockTolerance,
	};
	let jwt: VerifyRouterJwtConfig;
	if (mode === "verify") {
		const verifying = { ...jwtWire, validate: true as const };
		assertVerifyRouterJwtConfig(verifying, {
			caller: "createApp",
			path: "oauth.jwt",
			verifyCondition: 'oauth.jwt.mode is "verify"',
		});
		const keyResolver = await keyResolverRegistry.get(jwtWire.algorithm)(jwtWire);
		jwt = {
			validate: true,
			key: keyResolver.key,
			algorithms: keyResolver.algorithms,
			issuer: verifying.issuer,
			audience: verifying.audience,
			tokenType: verifying.tokenType,
			...bounds,
		};
	} else if (mode === "insecure-decode") {
		// The mode string is the consent — see the schema's `mode` doc comment.
		jwt = { validate: false, allowInsecureDecode: true, ...bounds };
		// error, not warn: a deployment that reaches this line accepts unsigned
		// tokens, and a fleet filtering at level=error must still see it (#106).
		logger.error({ mode: "insecure-decode" }, "jwt_validation_disabled");
	} else {
		throw new Error(
			`createApp: oauth.jwt.mode must be "verify" or "insecure-decode", got ${JSON.stringify(mode)}`,
		);
	}

	// 7. Resolve caller authentication (#108). The bearer token establishes the
	// subject a decision is about; it never establishes which service supplied
	// `resource` / `action` / `context`. Without this gate the endpoint is a
	// decision oracle for anyone who can route to the port.
	//
	// Shape-checked first for the same reason `oauth.jwt` is: `createApp` also
	// accepts hand-built configs, and `resolveCallerAuth` indexes into the block.
	assertConfigObject(config.http, "http");
	const callerAuth = resolveCallerAuth(config.http, {
		caller: "createApp",
		path: "http.callerAuth",
	});
	if (!callerAuth) {
		if (CALLER_AUTH_REQUIRED) {
			// Reached only once the policy constant is flipped — see its doc comment.
			throw new Error(
				"createApp: http.callerAuth.token is required (caller authentication is mandatory)",
			);
		}
		if (!isLoopbackBindAddress(config.http.hostname)) {
			// The genuinely dangerous combination, named rather than blocked: a
			// port reachable from off-host that will answer any caller. Warning
			// keeps container deployments and the cross-repo E2E working while
			// still telling their operators what they are running.
			logger.warn({ hostname: config.http.hostname }, "unauthenticated_non_loopback_bind");
		}
	}

	// 8. Build Express app
	const app = express();
	const prefix = config.http.pathPrefix || "/";
	// Healthcheck stays open: an orchestrator probe has no credential to present,
	// and it reveals nothing a decision does.
	app.use(prefix, createHealthcheckRouter());
	if (callerAuth) {
		// Ahead of the verify router, so a rejected caller is answered before the
		// request body is parsed and before any pipeline runs.
		app.use(prefix, createCallerAuthMiddleware(callerAuth, logger));
	}
	app.use(
		prefix,
		createVerifyRouter({
			jwt,
			logger,
			resourceParser,
			attributePipeline: new AttributePipeline(attributeCollectors),
			rulePipeline: new RulePipeline(ruleCollectors),
			evaluateOptions: { onEmptyRuleSet: config.rule.onEmptyRuleSet },
			maxBatchSize: config.verify.maxBatchSize,
		}),
	);

	return app;
}
