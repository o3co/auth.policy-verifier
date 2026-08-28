// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type CollectorLimits,
	type ResolvedCollectorLimits,
	resolveCollectorLimits,
	runCollectors,
} from "./collectorLimits.mjs";
import type { CollectorRequest, Rule, RuleCollector } from "./types.mjs";

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

	/** Runs every collector under the pipeline's bounds and returns the flattened rule list. */
	async collect(request: CollectorRequest): Promise<Rule[]> {
		return (await runCollectors(this.collectors, request, this.limits, "rule")).flat();
	}
}
