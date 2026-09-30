// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The port decisions are counted through; `observability/metrics.mts`
 * implements it with prom-client and serves it over express. It is its own
 * module so that code which only reports — above all the decision, which must
 * reach neither express nor prom-client (`decision/__tests__/dependencies.test.mts`)
 * — imports nothing of the implementation, not even a type.
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

/** One collector failure that kept a decision from being made, as the metrics seam sees it. */
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
	 * Called once per collector failure the router logs — a
	 * `collector_timeout` deny, or a `verify_internal_error` a collector threw.
	 * Optional: an implementation without it still satisfies the seam and does
	 * not count them.
	 */
	observeCollectorFailure?(observation: CollectorFailureObservation): void;
}

/**
 * Counts a failure a collector is answerable for. Called beside each
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
