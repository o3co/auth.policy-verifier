// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * What a collector fan-out is allowed to cost, and the one runner that enforces
 * it.
 *
 * Collectors call databases and HTTP APIs on the authorization hot path. A
 * bare `Promise.all` has no deadline, no cancellation and no bound on how much
 * work it starts: one collector holding a dead socket would hold the decision
 * with it, siblings would keep running after one had failed the request, and
 * a dependency slowdown would pile up in-flight work rather than shed it.
 *
 * Three bounds, because each catches something the others cannot:
 *
 * - a **per-collector timeout**, which names the collector that stalled;
 * - an **end-to-end deadline**, which catches a fan-out where nothing overran
 *   its own budget but the total still did — the shape a queue produces;
 * - a **concurrency bound**, which stops a slow dependency from turning one
 *   request into an unbounded number of simultaneous outbound calls.
 *
 * And one rule over all three: **a bound that trips fails the collect.** It
 * never resolves with what it managed to gather. Partial attributes weaken a
 * rule's inputs and partial rules weaken the policy itself — an empty rule set
 * is an *allow* under `onEmptyRuleSet: "allow"` — so "return what we have"
 * turns a timeout into a permit. See the fail-closed suite in
 * `__tests__/collectorLimits.test.mts`.
 */

import { CollectorTimeoutError } from "./errors.mjs";
import { describeCollector, type FailureRecord } from "./failureSource.mjs";
import type { CollectorContext, CollectorRequest } from "./types.mjs";

/**
 * How long one collector may take before it is cancelled and the decision
 * fails. A collector does one lookup against a dependency the deployment runs,
 * and a healthy one answers in milliseconds; two seconds is far past "slow"
 * and well short of the timeouts callers put on the verify call, so the
 * verifier is the layer that notices, and it can say *which* collector.
 */
export const DEFAULT_COLLECTOR_TIMEOUT_MS = 2_000;

/**
 * How long the whole fan-out may take, per pipeline, however many collectors
 * are configured: more than one collector's budget and less than the sum of
 * several. Under the concurrency cap collectors queue, so the per-collector
 * timeout cannot bound a *set*; this bounds the answer the caller experiences.
 */
export const DEFAULT_COLLECT_DEADLINE_MS = 5_000;

/**
 * How many collectors may be in flight at once, per pipeline, per decision.
 *
 * Eight: more than the collector set of any deployment this project has seen,
 * so a normal configuration still fans out in one wave. The cap removes the
 * tail — dozens of collectors multiplying into simultaneous outbound calls
 * against a dependency that has started to slow down. It is a ceiling on
 * pathology, not a tuning parameter.
 *
 * Per **decision**: a `POST /verify/batch` multiplies it by however many
 * entries are decided at once, and bounding that product is the batch route's
 * job (`verify.batchConcurrency`), not this cap's.
 */
export const DEFAULT_COLLECTOR_CONCURRENCY = 8;

/**
 * How long one asynchronous rule may take to answer — the same budget
 * as one collector, for the same reason: it is one call to a dependency the
 * deployment runs (a policy engine), a healthy one answers in milliseconds,
 * and the verifier is the layer that can say *which* rule stalled. Defined in
 * terms of the collector's so the two cannot drift apart.
 */
export const DEFAULT_RULE_TIMEOUT_MS: number = DEFAULT_COLLECTOR_TIMEOUT_MS;

/**
 * How long the whole rule phase may take — every asynchronous rule of one
 * decision, together. The same five seconds as a collector
 * fan-out, for the same reason: a per-rule budget cannot bound a set, and
 * groups are evaluated one after another, so rules that each finish inside
 * their own budget still add up. Defined in terms of the collect deadline so
 * the two phases cannot drift apart.
 */
export const DEFAULT_EVALUATE_DEADLINE_MS: number = DEFAULT_COLLECT_DEADLINE_MS;

/**
 * The largest delay a timer can actually hold: 2^31 - 1 milliseconds, about
 * 24.8 days. Node stores a `setTimeout` delay in a signed 32-bit integer and
 * silently clamps anything above to ~1 ms — so a bigger "budget" is not a
 * generous bound but a timer that fires almost immediately, cancelling every
 * collector and denying every decision. A millisecond knob above this
 * is refused wherever one is read.
 */
export const MAX_TIMER_MS = 2_147_483_647;

/** Which fan-out a bound was tripped in. Carried into the failure message. */
export type CollectorPipeline = "attribute" | "rule";

/**
 * Bounds on a pipeline's collector fan-out. Every field is optional and falls
 * back to the shipped default, so a pipeline constructed with nothing is still
 * bounded — a library consumer does not opt into being fail-closed.
 *
 * A deployment sets these through `verify.collectorTimeoutMs`,
 * `verify.collectorDeadlineMs` and `verify.collectorConcurrency`; the server
 * holds those to the same bound at both of its config boundaries (AGENTS.md,
 * "Two-Boundary Config Validation") and hands the resolved numbers here.
 */
export interface CollectorLimits {
	/** Milliseconds one collector may take. Defaults to {@link DEFAULT_COLLECTOR_TIMEOUT_MS}. */
	collectorTimeoutMs?: number;
	/** Milliseconds the whole fan-out may take. Defaults to {@link DEFAULT_COLLECT_DEADLINE_MS}. */
	deadlineMs?: number;
	/** Collectors in flight at once. Defaults to {@link DEFAULT_COLLECTOR_CONCURRENCY}. */
	concurrency?: number;
}

/**
 * Per-call options for `AttributePipeline.collect` / `RulePipeline.collect`.
 * Separate from the request, because nothing here is a fact about the request
 * and none of it reaches a collector.
 */
export interface CollectOptions {
	/**
	 * Where this decision's failures are recorded — which collector
	 * rejected, overran its budget, or which pipeline overran its deadline. One
	 * per decision; see `FailureRecord`. Omitted, nothing is recorded, and the
	 * collect behaves exactly as without it.
	 */
	failures?: FailureRecord;
}

/** {@link CollectorLimits} with every default filled in. */
export interface ResolvedCollectorLimits {
	collectorTimeoutMs: number;
	deadlineMs: number;
	concurrency: number;
}

/**
 * Fills in the defaults and refuses a limit that is not a positive whole
 * number — or a millisecond budget above what a timer can hold — naming the
 * field.
 *
 * Refused rather than repaired, and at construction rather than at the first
 * request: `concurrency: 0` would start no collector and resolve with an empty
 * attribute map and an empty rule set, the fail-open this module exists to
 * close; a timeout past {@link MAX_TIMER_MS} is clamped by `setTimeout` to
 * ~1 ms, a bound nobody wrote that denies everything.
 *
 * This check is weaker than the config layer's `resolveBound`, not a second
 * opinion: every number `resolveBound` produces for these knobs is a positive
 * integer within the timer ceiling, so the two cannot reach different
 * verdicts on a configured value. It catches a hand-written call that never
 * met a config boundary.
 */
export function resolveCollectorLimits(limits?: CollectorLimits): ResolvedCollectorLimits {
	return {
		collectorTimeoutMs: timer(
			limits?.collectorTimeoutMs,
			DEFAULT_COLLECTOR_TIMEOUT_MS,
			"collectorTimeoutMs",
		),
		deadlineMs: timer(limits?.deadlineMs, DEFAULT_COLLECT_DEADLINE_MS, "deadlineMs"),
		concurrency: positive(limits?.concurrency, DEFAULT_COLLECTOR_CONCURRENCY, "concurrency"),
	};
}

/**
 * The budget one asynchronous rule runs under. Fills in the default and
 * refuses what {@link resolveCollectorLimits} refuses, naming `ruleTimeoutMs`.
 * The server package holds `verify.ruleTimeoutMs` to the same bound at both
 * of its config boundaries and hands the resolved number to `evaluate()`.
 */
export function resolveRuleTimeoutMs(value?: number): number {
	return timer(value, DEFAULT_RULE_TIMEOUT_MS, "ruleTimeoutMs");
}

/**
 * The deadline the whole rule phase runs under. Fills in the default and
 * refuses what {@link resolveRuleTimeoutMs} refuses, naming `evaluateDeadlineMs`.
 */
export function resolveEvaluateDeadlineMs(value?: number): number {
	return timer(value, DEFAULT_EVALUATE_DEADLINE_MS, "evaluateDeadlineMs");
}

function positive(value: number | undefined, fallback: number, field: string): number {
	if (value === undefined) return fallback;
	// `Number.isInteger` is false for NaN and both infinities, which is the
	// point: an infinite bound is the unbounded case these limits exist to
	// prevent, spelled as a setting.
	if (!Number.isInteger(value) || value < 1) {
		throw new RangeError(`${field} must be a positive integer, got ${String(value)}`);
	}
	return value;
}

/** A millisecond budget: positive, and small enough for a timer to hold. */
function timer(value: number | undefined, fallback: number, field: string): number {
	const resolved = positive(value, fallback, field);
	if (resolved > MAX_TIMER_MS) {
		throw new RangeError(
			`${field} must be at most ${MAX_TIMER_MS} milliseconds, got ${String(value)}`,
		);
	}
	return resolved;
}

/** The half of a collector this runner uses — either kind produces some `T`. */
interface Collecting<T> {
	collect(context: CollectorContext): Promise<T>;
}

/**
 * Runs every collector under the configured bounds and returns their results in
 * collector order.
 *
 * @throws {CollectorTimeoutError} when a collector overruns its own budget or
 * the fan-out overruns its deadline.
 * @throws whatever a collector rejected with, or the caller's abort reason —
 * both unchanged, so a store outage still surfaces as the store's own error.
 * Where each failure came from is recorded in `failures` beside the error
 * rather than wrapped around it.
 *
 * It never resolves partially: on any failure the results gathered so far are
 * discarded and every sibling still running is cancelled.
 */
export async function runCollectors<T>(
	collectors: readonly Collecting<T>[],
	request: CollectorRequest,
	limits: ResolvedCollectorLimits,
	pipeline: CollectorPipeline,
	failures?: FailureRecord,
): Promise<T[]> {
	if (collectors.length === 0) return [];

	// The fan-out's own controller. It aborts for three reasons — the deadline,
	// the caller's signal, or a sibling having already failed the request — and
	// every per-collector signal hangs off it, so any one of them cancels the
	// whole wave.
	const fanOut = new AbortController();
	const deadline = setTimeout(() => {
		const expired = new CollectorTimeoutError({
			pipeline,
			limit: "deadline",
			timeoutMs: limits.deadlineMs,
		});
		failures?.record(expired, { kind: "deadline", pipeline });
		fanOut.abort(expired);
	}, limits.deadlineMs);

	const caller = request.signal;
	const onCallerAbort = () => fanOut.abort(caller?.reason);
	if (caller?.aborted) {
		fanOut.abort(caller.reason);
	} else {
		caller?.addEventListener("abort", onCallerAbort, { once: true });
	}

	const results = new Array<T>(collectors.length);
	let next = 0;

	/**
	 * Pulls collectors off the shared cursor until there are none left.
	 *
	 * It does not test the fan-out itself before each turn: `runOne` refuses an
	 * abandoned decision at the point the collector would actually be invoked,
	 * and its refusal propagates out of this loop, which sheds the rest of the
	 * queue. One check, where the thing it protects happens.
	 */
	const lane = async (): Promise<void> => {
		while (next < collectors.length) {
			const index = next++;
			results[index] = await runOne(
				collectors[index],
				index,
				request,
				limits,
				pipeline,
				fanOut,
				failures,
			);
		}
	};

	try {
		await Promise.all(
			// One lane per permit, never more than there is work for.
			Array.from({ length: Math.min(limits.concurrency, collectors.length) }, () => lane()),
		);
		return results;
	} catch (cause) {
		// Cancel the siblings still in flight. `Promise.all` has already handed us
		// the first failure, and without this the rest would keep holding their
		// sockets open for a decision that has already failed.
		fanOut.abort(cause);
		throw cause;
	} finally {
		clearTimeout(deadline);
		// The caller's signal outlives this collect — a listener left on it is a
		// leak per decision, not per process.
		caller?.removeEventListener("abort", onCallerAbort);
	}
}

/**
 * Runs one collector under its own timeout, with a signal that aborts when
 * either that timeout or the fan-out does.
 *
 * The budget starts when the collector starts, not when the fan-out did:
 * under the concurrency cap a collector waits its turn, and charging it for
 * the queue would refuse work that had not yet begun.
 *
 * A collector whose decision is already lost is **not invoked at all**. An
 * aborted signal is not enough: `fetch` refuses one before connecting, but a
 * driver call that takes no signal, or whatever a collector does before its
 * first signal-aware call, still goes out — an outbound call for an answer
 * nobody will read, often against the dependency whose slowness abandoned the
 * decision. Refusing to start is the point of a concurrency bound; starting
 * and then cancelling only bounds how long the amplification lasts.
 */
async function runOne<T>(
	collector: Collecting<T>,
	index: number,
	request: CollectorRequest,
	limits: ResolvedCollectorLimits,
	pipeline: CollectorPipeline,
	fanOut: AbortController,
	failures: FailureRecord | undefined,
): Promise<T> {
	if (fanOut.signal.aborted) {
		// The reason is the fan-out's, not a timeout of this collector's own: it
		// never ran, so it never overran anything. The *set* ended — the deadline,
		// a sibling's failure, or the caller leaving — and the failure keeps
		// naming whichever it was. Rethrowing rather than resolving is what keeps
		// the collect fail-closed: a skipped collector must not read as one that
		// contributed nothing.
		throw fanOut.signal.reason;
	}

	const own = new AbortController();
	const inheritAbort = () => own.abort(fanOut.signal.reason);
	fanOut.signal.addEventListener("abort", inheritAbort, { once: true });

	const name = describeCollector(collector, index, pipeline);
	const source = { kind: "collector", pipeline, collector: name } as const;
	const timeout = setTimeout(() => {
		const expired = new CollectorTimeoutError({
			pipeline,
			limit: "collector",
			timeoutMs: limits.collectorTimeoutMs,
			collector: name,
		});
		failures?.record(expired, source);
		own.abort(expired);
	}, limits.collectorTimeoutMs);

	const cancelled = rejectOnAbort(own.signal);
	try {
		const context: CollectorContext = { ...request, signal: own.signal };
		// Constructed rather than called bare, so a collector that throws before
		// returning a promise is attributed exactly as one that rejects.
		const collected = new Promise<T>((resolve) => resolve(collector.collect(context))).catch(
			(error: unknown) => {
				// Only a failure of the collector's own is its to answer for.
				// Once its signal has aborted — a sibling failed, the deadline
				// passed, the caller left — a collector honouring the signal
				// rejects with that reason, and naming it here would blame it for
				// the failure it was cancelled because of.
				if (!own.signal.aborted) failures?.record(error, source);
				throw error;
			},
		);
		// Raced rather than awaited: a collector that ignores its signal — the
		// hung-socket case this is all for — would otherwise never settle, and a
		// bound only the cooperative respect is not a bound.
		return await Promise.race([collected, cancelled.promise]);
	} finally {
		clearTimeout(timeout);
		cancelled.dispose();
		fanOut.signal.removeEventListener("abort", inheritAbort);
	}
}

/**
 * A promise that rejects with `signal.reason` when it aborts and otherwise
 * never settles, plus the way to unsubscribe it once the race is over.
 *
 * **Precondition: `signal` is not yet aborted** — a listener added to an
 * aborted signal never fires, so the promise would hang. Both callers create
 * the controller just above, having refused what was already lost: `runOne`
 * an abandoned fan-out, `evaluate`'s `runAsyncRule` an aborted caller or a
 * spent rule phase. There is no defensive branch: it would be unreachable,
 * and so untested. A caller that cannot honour the precondition should reject
 * before calling.
 */
export function rejectOnAbort(signal: AbortSignal): {
	promise: Promise<never>;
	dispose: () => void;
} {
	// `reject` is captured rather than the whole body being written inside the
	// executor, so there is no placeholder `dispose` waiting to be overwritten.
	// The executor runs synchronously, so it is assigned before the next line.
	let reject!: (reason: unknown) => void;
	const promise = new Promise<never>((_, rejectPromise) => {
		reject = rejectPromise;
	});
	const onAbort = () => reject(signal.reason);
	signal.addEventListener("abort", onAbort, { once: true });
	return { promise, dispose: () => signal.removeEventListener("abort", onAbort) };
}
