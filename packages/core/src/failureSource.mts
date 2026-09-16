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
 * would break both.
 *
 * **Recorded per decision, not per error object.** The record is a
 * {@link FailureRecord} the caller creates for one decision and hands to both
 * pipelines and the evaluator. Nothing is kept process-wide: one error object
 * is routinely shared — a memoised downstream call, a circuit breaker's cached
 * failure — and an association keyed by the object alone let a concurrent
 * decision's record overwrite this one's before its caller had read it.
 */

import type { CollectorPipeline } from "./collectorLimits.mjs";

/**
 * Where a failure came from.
 *
 * - `collector` — one collector: it rejected or threw, or overran its own
 *   budget. Named as {@link describeCollector} names it, the same name
 *   `CollectorTimeoutError.collector` carries.
 * - `deadline` — a pipeline's fan-out as a whole overran its deadline. No one
 *   collector is answerable, so none is named.
 * - `rule` — one rule: its `verify` threw, its `decide` rejected, or it overran
 *   a rule budget. Named by `ruleType` and `code` as the rule declared them.
 *
 * Every source is recorded by the runner or the evaluator itself, never read
 * off the error, so a collector cannot claim to be something else by throwing
 * a `CollectorTimeoutError` it built.
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
			kind: "deadline";
			pipeline: CollectorPipeline;
	  }
	| {
			kind: "rule";
			ruleType: string;
			code: string;
	  };

/**
 * The failures of **one** decision and where each came from.
 *
 * Create one per decision, and hand the same one to
 * `attributePipeline.collect(request, { failures })`,
 * `rulePipeline.collect(request, { failures })` and
 * `evaluate(attrs, rules, { failures })`; then ask {@link sourceOf} with
 * whatever the decision was failed with. Sharing one across decisions brings
 * back exactly the cross-talk it exists to prevent.
 *
 * Keyed by the value that was thrown, primitives included — a record lives as
 * long as its decision, so nothing is retained. **The first source recorded
 * for a value wins**: when two collectors of one decision fail with the same
 * shared object, the one whose rejection landed first is named, which is the
 * one a `Promise.all` over them reports.
 */
export class FailureRecord {
	private readonly sources = new Map<unknown, FailureSource>();

	/**
	 * Records that `error` came from `source`, unless something already claimed
	 * it. Called by the collector runner and the evaluator; a hand-written
	 * pipeline may call it the same way.
	 */
	record(error: unknown, source: FailureSource): void {
		if (!this.sources.has(error)) this.sources.set(error, source);
	}

	/**
	 * Where `error` came from, or `undefined` when nothing recorded it — a
	 * caller's abort reason (a rejection after a collector's or rule's own
	 * signal aborted belongs to whatever aborted it), or an error from anywhere
	 * else.
	 */
	sourceOf(error: unknown): FailureSource | undefined {
		return this.sources.get(error);
	}
}

/**
 * Longest class name a collector's description carries. A class name is set
 * in code, and a name longer than this is not a name an operator wrote.
 */
const MAX_COLLECTOR_CLASS_NAME_LENGTH = 64;

/** A JavaScript identifier, as a class declaration spells its name. */
const CLASS_NAME = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/**
 * Names a collector the way an operator finds it in config: by its position in
 * the pipeline's list, spelled as the server's config path — `createApp` builds
 * each pipeline from `attribute.collectors` / `rule.collectors` in order — and
 * by class, when it has one. A collector wired as an object literal has only
 * its position.
 *
 * The class name is used only when it is identifier-shaped and at most
 * {@link MAX_COLLECTOR_CLASS_NAME_LENGTH} characters: `name` is an ordinary
 * property a collector can redefine, and this string becomes a log field and a
 * metric label. Every part is otherwise fixed when the pipeline is built.
 */
export function describeCollector(
	collector: object,
	index: number,
	pipeline: CollectorPipeline,
): string {
	const position = `${pipeline}.collectors[${index}]`;
	const name: unknown = collector.constructor?.name;
	return typeof name === "string" &&
		name !== "Object" &&
		name.length <= MAX_COLLECTOR_CLASS_NAME_LENGTH &&
		CLASS_NAME.test(name)
		? `${position} (${name})`
		: position;
}
