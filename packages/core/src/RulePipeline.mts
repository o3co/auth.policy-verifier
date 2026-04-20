// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, Rule, RuleCollector } from "./types.mjs";

/**
 * Fan-out aggregator that runs every `RuleCollector` in parallel and flattens
 * their results into a single `Rule[]`. Unlike `AttributePipeline`, rules do not
 * merge — each collector's rules are simply concatenated.
 */
export class RulePipeline {
	constructor(private collectors: RuleCollector[]) {}

	/** Runs every collector in parallel and returns the flattened rule list. */
	async collect(context: CollectorContext): Promise<Rule[]> {
		const results = await Promise.all(this.collectors.map((c) => c.collect(context)));
		return results.flat();
	}
}
