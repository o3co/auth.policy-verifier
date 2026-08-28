// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type CollectorLimits,
	type ResolvedCollectorLimits,
	resolveCollectorLimits,
	runCollectors,
} from "./collectorLimits.mjs";
import type { AttributeCollector, Attributes, CollectorRequest } from "./types.mjs";

/**
 * Fan-out aggregator that runs every `AttributeCollector` in parallel and merges
 * their results into a single `Attributes` map.
 *
 * Merge semantics: when the same key is produced by multiple collectors,
 * array-valued entries concatenate (in collector order), and non-array values
 * are overwritten by later collectors.
 *
 * The fan-out is bounded (#115): each collector gets its own timeout and an
 * `AbortSignal`, the wave as a whole gets a deadline, and only so many
 * collectors run at once. A bound that trips **fails the collect** — see
 * {@link CollectorLimits} and `collectorLimits.mts` for why a partial map is
 * never returned.
 */
export class AttributePipeline {
	private readonly limits: ResolvedCollectorLimits;

	constructor(
		private collectors: AttributeCollector[],
		limits?: CollectorLimits,
	) {
		// Resolved once, here, so an unusable bound is a construction failure
		// rather than a surprise on the first request that needed it.
		this.limits = resolveCollectorLimits(limits);
	}

	/** Runs every collector under the pipeline's bounds and returns the merged map. */
	async collect(request: CollectorRequest): Promise<Attributes> {
		return merge(await runCollectors(this.collectors, request, this.limits, "attribute"));
	}
}

/**
 * Merges attribute maps into a single map. Array-valued entries concatenate
 * in input order; non-array values are overwritten by later maps.
 */
function merge(maps: Attributes[]): Attributes {
	const merged: Attributes = new Map();
	for (const map of maps) {
		for (const [key, value] of map) {
			const existing = merged.get(key);
			if (Array.isArray(existing) && Array.isArray(value)) {
				merged.set(key, [...existing, ...value]);
			} else {
				merged.set(key, value);
			}
		}
	}
	return merged;
}
