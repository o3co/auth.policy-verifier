// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { AttributeCollector, Attributes, CollectorContext } from "./types.mjs";

/**
 * Fan-out aggregator that runs every `AttributeCollector` in parallel and merges
 * their results into a single `Attributes` map.
 *
 * Merge semantics: when the same key is produced by multiple collectors,
 * array-valued entries concatenate (in collector order), and non-array values
 * are overwritten by later collectors.
 */
export class AttributePipeline {
	constructor(private collectors: AttributeCollector[]) {}

	/** Runs every collector in parallel and returns the merged attribute map. */
	async collect(context: CollectorContext): Promise<Attributes> {
		const results = await Promise.all(this.collectors.map((c) => c.collect(context)));
		return merge(results);
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
