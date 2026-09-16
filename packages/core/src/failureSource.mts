// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Which collector — or which rule — a failure came from (#200).
 *
 * A collector that rejects fails its decision, and so does a rule whose
 * `verify` throws or whose `decide` rejects. The transport answers either as a
 * fault, and the one thing its log line could not say was *where* the fault
 * was: the collector runner and the evaluator knew, and threw the error on
 * without saying.
 *
 * **Recorded beside the error, not wrapped around it.** `pipeline.collect` and
 * `evaluate()` are documented to reject with whatever the collector or rule
 * rejected with, unchanged — a store outage surfaces as the store's own error —
 * and a transport tells a deny from a fault by that error's class
 * (`CollectorTimeoutError` is a deny wherever it is thrown from). A wrapper
 * would break both: a caller matching its own error would stop matching, and a
 * collector that rethrows a nested pipeline's timeout would turn a deny into a
 * 500. So the attribution lives in a `WeakMap` keyed by the error object, which
 * retains nothing and changes nothing about what is thrown.
 *
 * What that costs is stated rather than hidden: a rejection that is not an
 * object — `throw "down"` — cannot be a key, so it cannot be named. Throw an
 * `Error`.
 */

import type { CollectorPipeline } from "./collectorLimits.mjs";

/**
 * Where a failure came from.
 *
 * `collector` is the name {@link describeCollector} gives it — the same one
 * `CollectorTimeoutError.collector` carries — and a rule is named by
 * `ruleType` and `code`, the two things an operator can find it by in config.
 * Neither ever carries anything read from the request.
 */
export type FailureSource =
	| {
			kind: "collector";
			/** The fan-out the collector ran in. */
			pipeline: CollectorPipeline;
			/** `attribute.collectors[1] (EntitlementStoreCollector)`, or `rule.collectors[0]`. */
			collector: string;
	  }
	| {
			kind: "rule";
			ruleType: string;
			code: string;
	  };

const sources = new WeakMap<object, FailureSource>();

/**
 * The collector or rule `error` was thrown by, or `undefined` when no pipeline
 * or evaluator recorded one — an error from anywhere else, a caller's abort
 * reason, a timeout (which names its collector or rule on itself), or a
 * rejection that is not an object.
 */
export function failureSourceOf(error: unknown): FailureSource | undefined {
	return isKey(error) ? sources.get(error) : undefined;
}

/**
 * Records that `error` was thrown by `source`. The latest record wins: an error
 * object a store client reuses across requests is attributed to whichever
 * collector threw it last, which is the one whose decision is failing now.
 */
export function recordFailureSource(error: unknown, source: FailureSource): void {
	if (isKey(error)) sources.set(error, source);
}

/**
 * Names a collector the way an operator finds it in config: by its position in
 * the pipeline's list, spelled as the server's config path — `createApp` builds
 * each pipeline from `attribute.collectors` / `rule.collectors` in order — and
 * by class, when it has one. A collector wired as an object literal has only
 * its position.
 *
 * Every part is fixed when the pipeline is built, so the name is bounded by the
 * configuration and safe to use as a metric label.
 */
export function describeCollector(
	collector: object,
	index: number,
	pipeline: CollectorPipeline,
): string {
	const position = `${pipeline}.collectors[${index}]`;
	const name = collector.constructor?.name;
	return name && name !== "Object" ? `${position} (${name})` : position;
}

function isKey(value: unknown): value is object {
	return (typeof value === "object" && value !== null) || typeof value === "function";
}
