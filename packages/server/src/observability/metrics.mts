// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Prometheus metrics for the policy verifier.
 *
 * The shape follows auth.provider's `/metrics` so one Prometheus job and one
 * set of dashboard conventions serve both halves of the stack:
 * `http_request_duration_seconds` verbatim, application series under the
 * `auth_` family, Node process defaults under a per-service prefix.
 *
 * Every label is bounded:
 *
 * - `route` is the Express route pattern, never the URL, and unmatched
 *   requests collapse to `"unmatched"`.
 * - `method` is an allowlist; anything else is `"other"`.
 * - `code` is a rule's own `code`, which a rule collector can compute from the
 *   request, so it is capped.
 * - `collector` is a collector's position and identifier-shaped class name as
 *   the collector runner recorded it — never the name inside an error — or the
 *   list whose deadline ran out, or `"unattributed"`, capped as a backstop.
 *   `category` is a closed enum (`observability/failure.mts`).
 *
 * `resource` and `action` are not labels: they come straight out of the
 * request body, unbounded, and an open label mints a time series per distinct
 * value. They are on the per-decision log line instead
 * (`observability/decisionEvent.mts`).
 */

import express from "express";
import { Counter, collectDefaultMetrics, Histogram, Registry } from "prom-client";
// The port this implements lives apart from it, so that what only
// reports through it reaches neither express nor prom-client.
import type { DecisionMetrics } from "./decisionMetrics.mjs";

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
 * Deny codes come from the rules a deployment configured, but `code` is a field
 * on the `Rule` interface and a rule collector builds its rules per request, so
 * a third-party collector can derive a code from the resource it was asked
 * about. 32 is far more than any real pipeline distinguishes; `code="other"`
 * climbing is the signal that a rule is minting codes per request.
 */
export const MAX_DENY_CODE_LABELS = 32;

/**
 * Distinct `collector` label values published before the rest collapse into
 * `"other"`.
 *
 * A collector's name is what the collector runner recorded — its position and
 * its identifier-shaped class name — or, when a pipeline's deadline ran out,
 * the list itself (`attribute.collectors`, `rule.collectors`), or
 * `"unattributed"`: one value per collector that has failed, and at most three
 * more. The cap is a backstop: a class's `name` is an ordinary property, and
 * code can mint it per request.
 */
export const MAX_COLLECTOR_LABELS = 32;

/**
 * A label that admits at most `max` distinct values, first come first served,
 * and collapses the rest into `"other"` — so a deployment's real values are
 * published and only what arrives after them is folded.
 */
function cappedLabel(max: number): (value: string) => string {
	const published = new Set<string>();
	return (value) => {
		if (published.has(value)) return value;
		if (published.size >= max) return "other";
		published.add(value);
		return value;
	};
}

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
 * handles). Registered once and shared rather than per `createMetrics()` call:
 * these are facts about the process, and `collectDefaultMetrics` installs
 * collectors — a `PerformanceObserver` among them — that a second registration
 * would install again while publishing the same numbers.
 */
let processDefaults: Registry | undefined;

function processDefaultsRegistry(): Registry {
	if (!processDefaults) {
		processDefaults = new Registry();
		collectDefaultMetrics({ register: processDefaults, prefix: PROCESS_METRICS_PREFIX });
	}
	return processDefaults;
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
 * - `auth_decisions_total{decision}` — exactly two series: the allow/deny rate.
 *   A deny is a normal outcome for a decision point, so alert on a change in
 *   the ratio.
 * - `auth_denials_total{code}` — which rule is denying; the aggregate of the
 *   `decision` log line's `deniedBy`.
 * - `auth_decision_duration_seconds{decision}` — time inside the collector
 *   pipelines and the evaluator, distinct from the HTTP histogram: one
 *   `POST /verify/batch` request is up to `verify.maxBatchSize` decisions.
 * - `auth_collector_failures_total{collector,category}` — which fact source is
 *   failing decisions, and how: `category` is `collector_timeout` or
 *   `collector_threw`. The aggregate of the `collector` field on the
 *   `collector_timeout` and `verify_internal_error` log lines.
 * - `auth_policy_verifier_*` — Node process defaults.
 *
 * There is no per-dependency `up` gauge like auth.provider's
 * `auth_dependency_up`: its equivalent here is the JWKS endpoint, there is no
 * readiness-probe registry to sample, and a gauge fed from a hand-maintained
 * list of dependencies would drift. A JWKS outage shows as the
 * `jwt_verification_unavailable` log event, emitted at error so it can be
 * alerted on, and as `503` responses on the HTTP histogram.
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

	const collectorFailuresTotal = new Counter({
		name: "auth_collector_failures_total",
		help: "Collector failures that kept a decision from being made, by collector and category.",
		labelNames: ["collector", "category"] as const,
		registers: [registry],
	});

	const codeLabel = cappedLabel(MAX_DENY_CODE_LABELS);
	const collectorLabel = cappedLabel(MAX_COLLECTOR_LABELS);

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
		observeCollectorFailure({ collector, category }) {
			collectorFailuresTotal.inc({ collector: collectorLabel(collector), category });
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
