// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The seam decisions are counted through (#111, #200), apart from any one way
 * of counting them (#258).
 *
 * The decision and the verify router report through `DecisionMetrics` and
 * nothing more; `observability/metrics.mts` implements it with prom-client and
 * serves it over express. The port is its own module so that everything which
 * only reports — the decision above all, which must reach neither express nor
 * prom-client (`decision/__tests__/dependencies.test.mts`) — imports no part of
 * the implementation, not even a type: the dependency runs from the
 * implementation to the port and never back.
 */

import type { ClassifiedFailure, CollectorFailureCategory } from "./failure.mjs";

/** One decision, as the metrics seam sees it. */
export interface DecisionObservation {
	decision: "allow" | "deny";
	/**
	 * Deny code. Absent on an allow. A rule collector may compute it per
	 * request, so an implementation that labels by it must bound it — the
	 * Prometheus one caps it at `MAX_DENY_CODE_LABELS`.
	 */
	code?: string;
	/** How long collecting and evaluating took, in seconds. */
	durationSeconds: number;
}

/** One collector failure that kept a decision from being made, as the metrics seam sees it (#200). */
export interface CollectorFailureObservation {
	/**
	 * `attribute.collectors[1] (EntitlementStoreCollector)`, or the list itself
	 * (`attribute.collectors`) when the pipeline's deadline ran out. The
	 * Prometheus implementation caps it at `MAX_COLLECTOR_LABELS` when published.
	 */
	collector: string;
	category: CollectorFailureCategory;
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
	/**
	 * Called once per collector failure the router logs (#200) — a
	 * `collector_timeout` deny, or a `verify_internal_error` a collector threw.
	 * Optional, so an implementation written against the seam before it
	 * existed still satisfies it and simply does not count them.
	 */
	observeCollectorFailure?(observation: CollectorFailureObservation): void;
}

/**
 * Counts a failure a collector is answerable for (#200). Called beside each
 * log line that reports one, and only there, so the counter and the log
 * stream agree on how many there were: a timed-out batch entry is one line
 * and one count, and a batch that failed with a 500 — which speaks for the
 * whole request — is also one of each. No `metrics` counts nothing.
 */
export function countCollectorFailure(
	metrics: DecisionMetrics | undefined,
	failure: ClassifiedFailure,
): void {
	if ("collector" in failure) {
		metrics?.observeCollectorFailure?.({
			collector: failure.collector,
			category: failure.category,
		});
	}
}
