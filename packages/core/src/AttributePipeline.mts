// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Runs every attribute collector for a request under the collector bounds and
 * merges their maps into one `Attributes`, failing the collect on a tripped
 * bound, a collector's rejection or a conflicting scalar write.
 */

import {
	type CollectOptions,
	type CollectorLimits,
	type ResolvedCollectorLimits,
	resolveCollectorLimits,
	runCollectors,
} from "./collectorLimits.mjs";
import { AttributeConflictError } from "./errors.mjs";
import type { AttributeCollector, Attributes, CollectorRequest } from "./types.mjs";

/**
 * Fan-out aggregator that runs every `AttributeCollector` concurrently — up to
 * `CollectorLimits.concurrency` at a time, the rest queued behind them — and
 * merges their results into a single `Attributes` map: array-valued entries
 * concatenate (in collector order); a non-array value may be written once, or
 * re-written with the identical value, and two collectors writing different
 * values to it throw {@link AttributeConflictError} — see `merge` below.
 *
 * The fan-out is bounded: each collector gets its own timeout and an
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

	/**
	 * Runs every collector under the pipeline's bounds and returns the merged
	 * map. `options.failures` records where a failure came from.
	 */
	async collect(request: CollectorRequest, options?: CollectOptions): Promise<Attributes> {
		return merge(
			await runCollectors(this.collectors, request, this.limits, "attribute", options?.failures),
		);
	}
}

/**
 * Merges attribute maps into a single map. Array-valued entries concatenate
 * in input order. A non-array value may be written once — or re-written with
 * the **identical** value (same primitive, or same object reference); two
 * maps writing *different* values to the same scalar key throw
 * {@link AttributeConflictError}, which the transport answers as a deny: an
 * ambiguous attribute map is not something to authorize from.
 *
 * A scalar write still resets any array accumulation for its key, and a later
 * array still replaces an earlier scalar (pinned by tests); only the
 * scalar-vs-scalar disagreement is a conflict. Array fragments are collected
 * per key and concatenated once at the end, so a key many maps contribute to
 * (roles, permissions) is not re-copied per map.
 *
 * **The trap the union sets for collector authors.** Two collectors writing
 * the same scalar key disagree loudly; two writing the same *array* key never
 * disagree at all — the second one's entries are added. That is the point for
 * `roles` and `permissions`, which several collectors are meant to contribute
 * to. But a collector promoting caller-supplied data onto an engine-owned key
 * does not overwrite the deployment's value and lose the argument: it EXTENDS
 * it, silently, and the decision looks exactly like one the issuer granted.
 * So a collector reading untrusted input owes its destination keys a guard —
 * see `RESERVED_ATTRIBUTE_KEYS` in `keys.mts`, and
 * `RequestContextAttributeCollector` in builtins for the worked example.
 */
function merge(maps: Attributes[]): Attributes {
	const merged: Attributes = new Map();
	const fragments = new Map<string, unknown[][]>();
	for (const map of maps) {
		for (const [key, value] of map) {
			if (Array.isArray(value)) {
				const parts = fragments.get(key);
				if (parts === undefined) fragments.set(key, [value]);
				else parts.push(value);
			} else {
				// `Object.is`, not `===`: a NaN re-written as NaN is the same
				// value, not a disagreement.
				if (merged.has(key) && !Object.is(merged.get(key), value)) {
					throw new AttributeConflictError(key);
				}
				fragments.delete(key);
				merged.set(key, value);
			}
		}
	}
	for (const [key, parts] of fragments) {
		merged.set(key, parts.flat());
	}
	return merged;
}
