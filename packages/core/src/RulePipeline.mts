// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Runs every rule collector for a request under the collector bounds and
 * concatenates their rules, failing the collect rather than returning a partial
 * rule list.
 */

import {
	type CollectOptions,
	type CollectorLimits,
	type ResolvedCollectorLimits,
	resolveCollectorLimits,
	runCollectors,
} from "./collectorLimits.mjs";
import type { AnyRule, CollectorRequest, RuleCollector } from "./types.mjs";

/**
 * Fan-out aggregator that runs every `RuleCollector` in parallel and flattens
 * their results into a single `Rule[]`. Unlike `AttributePipeline`, rules do not
 * merge — each collector's rules are simply concatenated.
 *
 * The fan-out is bounded exactly as the attribute one is (#115), and failing
 * closed matters more here: a short rule list is a *weaker policy*, and an empty
 * one is an allow wherever a deployment set `onEmptyRuleSet: "allow"`. A bound
 * that trips fails the collect rather than returning the rules that arrived in
 * time.
 */
export class RulePipeline {
	private readonly limits: ResolvedCollectorLimits;

	constructor(
		private collectors: RuleCollector[],
		limits?: CollectorLimits,
	) {
		this.limits = resolveCollectorLimits(limits);
	}

	/**
	 * Runs every collector under the pipeline's bounds and returns the flattened
	 * rule list. `options.failures` records where a failure came from (#200).
	 */
	async collect(request: CollectorRequest, options?: CollectOptions): Promise<AnyRule[]> {
		return (
			await runCollectors(this.collectors, request, this.limits, "rule", options?.failures)
		).flat();
	}
}
