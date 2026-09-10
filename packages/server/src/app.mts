// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type AttributeCollectorFactory,
	AttributePipeline,
	type CollectorLimits,
	createConsoleLogger,
	type Logger,
	type Module,
	type PathResolver,
	Registry,
	type ResourceParserFactory,
	type RuleCollectorFactory,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import type { AppConfig } from "./config/application.schema.mjs";
import { assertConfigObject } from "./config/assertConfigObject.mjs";
import { NUMERIC_BOUNDS, resolveBound } from "./config/bounds.mjs";
import { CALLER_AUTH_REQUIRED } from "./config/defaults.mjs";
import {
	checkTokenAuthenticatorSelection,
	JWT_TOKEN_AUTHENTICATOR,
} from "./config/tokenAuthenticatorSelection.mjs";
import { createCallerAuthMiddleware, resolveCallerAuth } from "./http/callerAuth.mjs";
import { JwtTokenAuthenticatorFactory } from "./jwt/jwtTokenAuthenticatorFactory.mjs";
import type {
	KeyResolverFactory,
	ServerModuleContext,
	TokenAuthenticatorFactory,
} from "./jwt/keyResolver.mjs";
import { isLoopbackBindAddress } from "./net/loopback.mjs";
import { createMetrics } from "./observability/metrics.mjs";
import { createHealthcheckRouter } from "./routes/healthcheck.mjs";
import { createVerifyRouter } from "./routes/verify.mjs";

/** Options accepted by `createApp`. */
export interface CreateAppOptions {
	pathResolver: PathResolver;
	config: AppConfig;
	/**
	 * Initialized with the server's {@link ServerModuleContext}, so both a plain
	 * `Module` (collectors, rules, parsers) and a `Module<ServerModuleContext>`
	 * (key resolvers) are accepted.
	 */
	modules: Module<ServerModuleContext>[];
	/**
	 * Structured logger for boot-time warnings and the verify router's failure
	 * events. Pino-compatible (a pino instance satisfies it without an adapter).
	 * Defaults to the console-backed logger at `config.logging.level`, so
	 * failures are never silent even when nothing is wired.
	 */
	logger?: Logger;
}

/**
 * Where the liveness probe answers, under `config.http.pathPrefix`.
 *
 * `/_healthcheck` is the canonical path: the one every component of the stack
 * serves (auth.provider and auth.proxy already did — o3co/auth.provider#293
 * item 14) and the one the standalone image's `HEALTHCHECK` probes. This server
 * answered on `/healthcheck` before the stack settled on one spelling; it is
 * kept as a compatibility alias so an orchestrator probe config that was not
 * updated does not start failing on upgrade. Both paths give the same answer.
 */
const LIVENESS_PATHS = ["/_healthcheck", "/healthcheck"] as const;

/**
 * Builds the Express app with registries initialized by the supplied modules.
 *
 * Flow: (1) create registries, (2) run `mod.init` sequentially so later modules
 * can see earlier ones' registrations, (3) resolve concrete collectors /
 * resource parser / token authenticator from config, (4) mount the liveness probe
 * (`LIVENESS_PATHS`), the optional caller-auth gate and the `/verify` router
 * under the configured path prefix.
 *
 * `config.http.callerAuth.token` authenticates the *calling service* before any
 * decision work runs (#108). It is optional in this release; the liveness probe
 * is never gated. See `CALLER_AUTH_REQUIRED` in `config/defaults` for the
 * one-line change that makes it mandatory.
 *
 * `config.oauth.authenticator` selects how the subject is authenticated (#219):
 * `"jwt"` (the default) is the built-in bearer-JWT path below; any other name
 * must have been registered by a module on `tokenAuthenticatorRegistry`.
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
	const tokenAuthenticatorRegistry = new Registry<TokenAuthenticatorFactory>();
	// The built-in authenticator is the host's, not a module's (#219): registered
	// before any module runs, so it is always selectable, and — the registry
	// refusing a second registration — never silently replaced. A deployment
	// that authenticates another way registers under another name and selects
	// it with `oauth.authenticator`.
	tokenAuthenticatorRegistry.register(JWT_TOKEN_AUTHENTICATOR, JwtTokenAuthenticatorFactory);

	// 2. Initialize modules — each registers factory functions
	const context: ServerModuleContext = {
		pathResolver,
		config: config as unknown as Record<string, unknown>,
		attributeCollectorRegistry,
		ruleCollectorRegistry,
		resourceParserRegistry,
		keyResolverRegistry,
		tokenAuthenticatorRegistry,
	};

	for (const mod of modules) {
		await mod.init(context);
	}

	// 3. Resolve attribute collectors from config — call factory with config entry
	//
	// The bounds both pipelines run their collectors under (#115) are resolved
	// here because this is where the pipelines are built, which makes `createApp`
	// their runtime guard: a hand-built config reaches it with `AppConfigSchema`
	// never having run. Read through `resolveBound` with the same specs the
	// schema uses, so the two boundaries cannot disagree about what a value means
	// — see AGENTS.md, "Two-Boundary Config Validation".
	const collectorLimits: CollectorLimits = {
		collectorTimeoutMs: resolveBound(
			config.verify.collectorTimeoutMs,
			NUMERIC_BOUNDS.collectorTimeoutMs,
			"verify",
		),
		deadlineMs: resolveBound(
			config.verify.collectorDeadlineMs,
			NUMERIC_BOUNDS.collectorDeadlineMs,
			"verify",
		),
		concurrency: resolveBound(
			config.verify.collectorConcurrency,
			NUMERIC_BOUNDS.collectorConcurrency,
			"verify",
		),
	};

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

	// 6. Resolve the token authenticator (#219). `oauth.authenticator` names an
	// entry in the registry the modules just filled — the built-in `"jwt"` was
	// registered ahead of them in step 2 — and the selected factory is handed
	// the whole `oauth` block plus the host's plumbing. Selection is read
	// through the one function `AppConfigSchema` also uses, so a hand-built
	// config gets the schema's verdict in the schema's words — see AGENTS.md,
	// "Two-Boundary Config Validation". Shape-checked first for the reason
	// `http` is below: `createApp` accepts configs that never met the schema.
	assertConfigObject(config.oauth, "oauth");
	const selection = checkTokenAuthenticatorSelection(config.oauth);
	if (!selection.ok) {
		throw new Error(`createApp: ${selection.message}`);
	}
	if (!tokenAuthenticatorRegistry.has(selection.name)) {
		throw new Error(
			`createApp: oauth.authenticator names ${JSON.stringify(selection.name)}, but no module ` +
				"registered a token authenticator under that name",
		);
	}
	const authenticator = await tokenAuthenticatorRegistry.get(selection.name)(config.oauth, {
		logger,
		keyResolverRegistry,
	});

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
			// port reachable from off-host that will answer any caller.
			//
			// WARN, NOT REFUSE, and deliberately so. The network may legitimately
			// be the control — a private subnet, a pod-local service, a mesh
			// policy — and this process cannot see any of it; all it knows is the
			// address it was told to bind. A refusal would therefore break every
			// existing containerised deployment on upgrade (the shipped
			// `templates/standalone/docker-compose.yml` sets `HTTP_HOSTNAME=0.0.0.0`
			// precisely because loopback inside a container publishes nothing) in
			// exchange for a verdict it is not equipped to reach. `CALLER_AUTH_REQUIRED`
			// in `config/defaults` is where that judgement gets made, once, for
			// everyone — flipping it is the deliberate breaking change; this line
			// is the notice in the meantime.
			//
			// Both settings are named because neither one alone is the problem:
			// a non-loopback bind behind caller auth is fine, and no caller auth
			// on loopback is the documented default. The operator needs to know
			// which pair produced this and which half to change.
			logger.warn(
				{
					hostname: config.http.hostname,
					bindSetting: "http.hostname",
					callerAuthSetting: "http.callerAuth",
					exposure:
						"POST /verify and /verify/batch answer authorization decisions to any caller that can reach this port with a valid subject token — the endpoint is a decision oracle",
					remediation:
						"restrict the port to a private network, or set http.callerAuth.token (env HTTP_CALLER_AUTH_TOKEN) so the calling service authenticates itself",
				},
				"unauthenticated_non_loopback_bind",
			);
		}
	}

	// 8. Build Express app
	const app = express();
	const prefix = config.http.pathPrefix || "/";
	const metrics = createMetrics();
	// First of everything, so the request histogram covers the whole stack —
	// including the responses produced before any route runs, such as the
	// caller-auth gate's 401s. A surge of those is exactly what it exists to show.
	app.use(metrics.middleware);
	// The liveness probe stays open on both its canonical path and its alias:
	// an orchestrator probe has no credential to present, and it reveals nothing
	// a decision does.
	for (const path of LIVENESS_PATHS) {
		app.use(prefix, createHealthcheckRouter(path));
	}
	// `/metrics` is ungated for the same reason, and one more (#111). Prometheus
	// scrape configs carry `authorization`, `basic_auth` and `oauth2` — not an
	// arbitrary header — so gating it behind `http.callerAuth`'s `x-caller-token`
	// would make it unscrapable by a stock scraper, and the workaround would be
	// to hand the credential that authorizes DECISIONS to the monitoring system.
	// What it publishes is counts and latencies over bounded labels: no subject,
	// no resource, no action, nothing about any individual decision. The boundary
	// that protects it is the bind address, which is loopback by default (#108) —
	// see the README on reaching it from a scraper.
	app.use(prefix, metrics.router);
	if (callerAuth) {
		// Ahead of the verify router, so a rejected caller is answered before the
		// request body is parsed and before any pipeline runs.
		app.use(prefix, createCallerAuthMiddleware(callerAuth, logger));
	}
	app.use(
		prefix,
		createVerifyRouter({
			authenticator,
			logger,
			metrics: metrics.decisions,
			resourceParser,
			attributePipeline: new AttributePipeline(attributeCollectors, collectorLimits),
			rulePipeline: new RulePipeline(ruleCollectors, collectorLimits),
			evaluateOptions: { onEmptyRuleSet: config.rule.onEmptyRuleSet },
			maxBatchSize: config.verify.maxBatchSize,
			batchConcurrency: config.verify.batchConcurrency,
			// Forwarded rather than defaulted here (#118): the router resolves each
			// through the same `resolveBound` the schema used, so a hand-built config
			// reaching `createApp` gets the schema's verdict either way.
			maxBodyBytes: config.verify.maxBodyBytes,
			maxResourceLength: config.verify.maxResourceLength,
			maxActionLength: config.verify.maxActionLength,
			maxContextEntries: config.verify.maxContextEntries,
			maxContextValueLength: config.verify.maxContextValueLength,
			credentialToCollectors: config.verify.credentialToCollectors,
		}),
	);

	return app;
}
