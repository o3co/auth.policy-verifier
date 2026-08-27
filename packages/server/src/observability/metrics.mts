// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Prometheus metrics for the policy verifier (#111).
 *
 * Before this there was no counter of decisions by outcome and no scrape
 * endpoint, so "what is our allow/deny rate?" could only be answered by
 * grepping logs — and only if something was logging, which #111 is also about.
 *
 * The shape follows auth.provider's `/metrics` (its 39767d52) so one Prometheus
 * job and one set of dashboard conventions serve both halves of the stack:
 * `http_request_duration_seconds` verbatim, application series under the
 * `auth_` family, Node process defaults under a per-service prefix.
 *
 * ## Label bounding
 *
 * Every label here is bounded, and each one is bounded on purpose:
 *
 * - `route` is the Express route **pattern**, never the URL, and unmatched
 *   requests collapse to `"unmatched"`.
 * - `method` is an allowlist; anything else is `"other"`. Node's HTTP parser
 *   accepts any valid token, so `req.method` is as caller-controlled as a path.
 * - `code` is a rule's own `code`, which comes from the deployment's configured
 *   rules — but `Rule.code` is an interface field, and a rule collector *can*
 *   compute it from the request, so it is additionally capped.
 *
 * And two values are deliberately **not** labels at all: `resource` and
 * `action`. They come straight out of the request body, they are unbounded by
 * construction ("project:1", "project:2", …), and one label left open mints a
 * fresh time series per distinct value — which is how a metrics endpoint takes
 * down the monitoring that was supposed to watch it. They are on the
 * per-decision log line instead, which is the right medium for high-cardinality
 * facts: see `observability/decisionEvent.mts`.
 */

import express from "express";
import { Counter, collectDefaultMetrics, Histogram, Registry } from "prom-client";

/** Namespace for the Node process defaults, so they cannot collide with anything else scraped. */
const PROCESS_METRICS_PREFIX = "auth_policy_verifier_";

/** Default path the scrape endpoint is served from. */
export const DEFAULT_METRICS_PATH = "/metrics";

/**
 * Methods that get their own label value. Everything else is `"other"`.
 *
 * `req.method` is caller-controlled: Node's HTTP parser accepts any valid
 * token, so `FOO` and `M000001` reach here as readily as `GET`. Each distinct
 * value would mint a fresh histogram child carrying every bucket, and it is
 * reachable without any access to `/metrics` itself.
 */
const KNOWN_METHODS = new Set([
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"PATCH",
	"DELETE",
	"OPTIONS",
	"TRACE",
	"CONNECT",
]);

/**
 * Distinct `code` label values published before the rest collapse into
 * `"other"`.
 *
 * Deny codes come from the rules a deployment configured, which makes them
 * operator-bounded the same way a route pattern is — a builtin such as
 * `HasScope` carries a single constant `invalid_scope`. But `code` is a field
 * on the `Rule` interface, and a rule collector builds its rules per request,
 * so a third-party collector is free to derive a code from the resource it was
 * asked about. That is one edit away from an unbounded label in somebody
 * else's repository, so the cap is here rather than in a code review comment.
 *
 * 32 is far more than any real pipeline distinguishes, and the collapse is
 * visible: `code="other"` climbing is itself the signal that a rule is minting
 * codes per request.
 */
export const MAX_DENY_CODE_LABELS = 32;

function methodLabel(req: express.Request): string {
	return KNOWN_METHODS.has(req.method) ? req.method : "other";
}

/**
 * Route label for a request.
 *
 * Express only fills `req.route` once a handler has matched. Labelling by
 * `req.path` instead would mint a series per distinct URL — and this server is
 * reached by 404 probes from anything that can route to the port.
 */
function routeLabel(req: express.Request): string {
	const route = (req as express.Request & { route?: { path?: string } }).route?.path;
	if (typeof route === "string" && route.length > 0) {
		return req.baseUrl ? `${req.baseUrl}${route === "/" ? "" : route}` : route;
	}
	return "unmatched";
}

/**
 * Process-wide registry holding the Node defaults (event-loop lag, heap, GC,
 * handles).
 *
 * Registered once and shared, rather than per `createMetrics()` call: these are
 * facts about the process, not about an app instance, and `collectDefaultMetrics`
 * installs collectors — a `PerformanceObserver` among them — that a second
 * registration would install a second copy of while publishing the same numbers.
 * Building two apps in one process (every test file here does) must not cost two.
 */
let processDefaults: Registry | undefined;

function processDefaultsRegistry(): Registry {
	if (!processDefaults) {
		processDefaults = new Registry();
		collectDefaultMetrics({ register: processDefaults, prefix: PROCESS_METRICS_PREFIX });
	}
	return processDefaults;
}

/** One decision, as the metrics seam sees it. */
export interface DecisionObservation {
	decision: "allow" | "deny";
	/** Deny code. Absent on an allow; bounded by {@link MAX_DENY_CODE_LABELS} when present. */
	code?: string;
	/** How long collecting and evaluating took, in seconds. */
	durationSeconds: number;
}

/**
 * The narrow seam the verify router reports decisions through.
 *
 * An interface rather than the concrete registry, so the router carries no
 * dependency on prom-client and a deployment can count decisions somewhere
 * else entirely.
 */
export interface DecisionMetrics {
	observe(observation: DecisionObservation): void;
}

/** Options accepted by {@link createMetrics}. */
export interface CreateMetricsOptions {
	/** Path the scrape endpoint is mounted at. Defaults to `/metrics`. */
	readonly path?: string;
}

export interface Metrics {
	/**
	 * Mount FIRST, ahead of every route and every gate: it times the whole
	 * downstream stack, so a request rejected by caller authentication is
	 * counted too — a spike of those is exactly what the series exist to show.
	 */
	readonly middleware: express.RequestHandler;
	/** The scrape endpoint. Mount it where a scraper can reach it unauthenticated. */
	readonly router: express.Router;
	/** Pass to `createVerifyRouter` so decisions are counted. */
	readonly decisions: DecisionMetrics;
}

/**
 * Builds the metrics middleware, the scrape endpoint and the decision seam.
 *
 * Published series:
 *
 * - `http_request_duration_seconds{method,route,status}` — request rate, error
 *   rate and latency in one histogram (the RED method). Same name and label set
 *   as auth.provider's, so one dashboard covers both services.
 * - `auth_decisions_total{decision}` — exactly two series, and the answer to
 *   "what is our allow/deny rate". A deny is a normal outcome for a decision
 *   point, so the alert worth writing is on a *change* in the ratio.
 * - `auth_denials_total{code}` — which rule is doing the denying. This is the
 *   aggregate counterpart of the `decision` log line's `deniedBy`.
 * - `auth_decision_duration_seconds{decision}` — time inside the collector
 *   pipelines and the evaluator, which is distinct from the HTTP histogram:
 *   one `POST /verify/batch` request is up to `verify.maxBatchSize` decisions.
 * - `auth_policy_verifier_*` — Node process defaults.
 *
 * **Deliberately not published yet:** a per-dependency `up` gauge like
 * auth.provider's `auth_dependency_up`. Its equivalent here is the JWKS
 * endpoint, and there is no readiness-probe registry to sample — a gauge built
 * from a second, hand-maintained list of dependencies is the drift auth.provider
 * avoided by sampling the probes. Until such a registry exists, a JWKS outage is
 * visible as the `jwt_verification_unavailable` log event, which is emitted at
 * error precisely so it can be alerted on.
 *
 * Each call builds its own registry, so several apps can be constructed in one
 * process without colliding on metric names.
 */
export function createMetrics(options: CreateMetricsOptions = {}): Metrics {
	const registry = new Registry();

	const requestDuration = new Histogram({
		name: "http_request_duration_seconds",
		help: "HTTP request latency in seconds, by method, route and status.",
		labelNames: ["method", "route", "status"] as const,
		// Matches auth.provider's, so the two services' latency panels are
		// directly comparable.
		buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
		registers: [registry],
	});

	const decisionsTotal = new Counter({
		name: "auth_decisions_total",
		help: "Authorization decisions, by outcome.",
		labelNames: ["decision"] as const,
		registers: [registry],
	});

	const denialsTotal = new Counter({
		name: "auth_denials_total",
		help: "Denied authorization decisions, by the code of the rule that refused.",
		labelNames: ["code"] as const,
		registers: [registry],
	});

	const decisionDuration = new Histogram({
		name: "auth_decision_duration_seconds",
		help: "Time spent collecting attributes and rules and evaluating them, in seconds.",
		labelNames: ["decision"] as const,
		// A decision is in-process work and normally sub-millisecond; the buckets
		// start far below the HTTP ones so a collector that starts reaching out to
		// a store is visible before it shows up as request latency.
		buckets: [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
		registers: [registry],
	});

	// Codes already published, so the cap admits the deployment's real codes on a
	// first-come basis and collapses only what arrives after them.
	const publishedCodes = new Set<string>();
	const codeLabel = (code: string): string => {
		if (publishedCodes.has(code)) return code;
		if (publishedCodes.size >= MAX_DENY_CODE_LABELS) return "other";
		publishedCodes.add(code);
		return code;
	};

	const middleware: express.RequestHandler = (req, res, next) => {
		const endTimer = requestDuration.startTimer();
		let observed = false;
		// Both terminal events behind a guard, not `finish` alone. `finish` covers
		// every response the server completes, and `req.route` is populated by
		// then — but a client or proxy that disconnects mid-handler emits `close`
		// WITHOUT `finish`, and those are disproportionately the slow and failing
		// requests these series exist to surface.
		const observe = () => {
			if (observed) return;
			observed = true;
			endTimer({
				method: methodLabel(req),
				route: routeLabel(req),
				status: String(res.statusCode),
			});
		};
		res.once("finish", observe);
		res.once("close", observe);
		next();
	};

	const decisions: DecisionMetrics = {
		observe({ decision, code, durationSeconds }) {
			decisionsTotal.inc({ decision });
			decisionDuration.observe({ decision }, durationSeconds);
			if (decision === "deny" && code !== undefined) {
				denialsTotal.inc({ code: codeLabel(code) });
			}
		},
	};

	const router = express.Router();
	router.get(options.path ?? DEFAULT_METRICS_PATH, async (_req, res) => {
		// The process defaults live in their own registry (see above), so the two
		// exposition texts are concatenated. They share no metric family — one is
		// entirely `auth_policy_verifier_`-prefixed — and the text format is a
		// concatenation of families, so this is a valid document.
		const [defaults, own] = await Promise.all([
			processDefaultsRegistry().metrics(),
			registry.metrics(),
		]);
		res.setHeader("Content-Type", registry.contentType);
		// A scrape must never be answered from a cache: a stale sample reports the
		// service healthy for exactly as long as the cache lives.
		res.setHeader("Cache-Control", "no-store");
		res.send(`${defaults.trimEnd()}\n${own.trimEnd()}\n`);
	});

	return { middleware, router, decisions };
}
