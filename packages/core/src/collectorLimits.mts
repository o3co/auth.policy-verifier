// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * What a collector fan-out is allowed to cost, and the one runner that enforces
 * it (#115).
 *
 * Collectors are designed to call databases and HTTP APIs — that is the whole
 * point of the layer — and both pipelines used to run them under a bare
 * `Promise.all`. A `Promise.all` has no deadline, no cancellation and no bound
 * on how much work it starts, so one collector holding a dead socket held the
 * decision with it, on the authorization hot path, for as long as the socket
 * took to notice. The siblings kept running after one of them had already
 * failed the request, and a dependency slowdown piled up unbounded in-flight
 * work rather than shedding it.
 *
 * Three bounds, because each catches something the others cannot:
 *
 * - a **per-collector timeout**, which names the collector that stalled;
 * - an **end-to-end deadline**, which catches a fan-out where nothing overran
 *   its own budget but the total still did — the shape a queue produces;
 * - a **concurrency bound**, which is what stops a slow dependency from turning
 *   one request into an unbounded number of simultaneous outbound calls.
 *
 * And one rule over all three: **a bound that trips fails the collect.** It
 * never resolves with what it managed to gather. Partial attributes weaken a
 * rule's inputs and partial rules weaken the policy itself — an empty rule set
 * is an *allow* under `onEmptyRuleSet: "allow"` — so "return what we have" is
 * the one implementation that turns a timeout into a permit. See the fail-closed
 * suite in `__tests__/collectorLimits.test.mts`.
 */

import { CollectorTimeoutError } from "./errors.mjs";
import type { CollectorContext, CollectorRequest } from "./types.mjs";

/**
 * How long one collector may take before it is cancelled and the decision
 * fails.
 *
 * Two seconds: a collector on this path is doing one lookup against a
 * dependency the deployment runs (a session store, a directory, an entitlement
 * API), and a healthy one answers in single-digit milliseconds. Two seconds is
 * far past "slow" and well short of the timeouts callers put on the verify call
 * itself, so the verifier is the layer that notices — and it can say *which*
 * collector, which a caller-side timeout never can.
 */
export const DEFAULT_COLLECTOR_TIMEOUT_MS = 2_000;

/**
 * How long the whole fan-out may take, per pipeline, however many collectors
 * are configured.
 *
 * Five seconds — deliberately more than one collector's budget and less than
 * the sum of several. The per-collector timeout cannot bound a *set*: with the
 * concurrency cap in play, collectors queue, and enough of them each finishing
 * just inside their own budget still adds up to a request nobody is waiting for
 * any more. This is the bound on the answer the caller actually experiences.
 */
export const DEFAULT_COLLECT_DEADLINE_MS = 5_000;

/**
 * How many collectors may be in flight at once, per pipeline, per decision.
 *
 * Eight: more than the collector set of any deployment this project has seen,
 * so a normal configuration still fans out in a single wave and nothing about
 * its latency changes. What the cap removes is the tail — a config with dozens
 * of collectors, or a `POST /verify/batch` of 50 entries, multiplying into
 * simultaneous outbound calls against a dependency that has just started to
 * slow down. That is the amplification the bound exists for; the number is a
 * ceiling on pathology, not a tuning parameter.
 */
export const DEFAULT_COLLECTOR_CONCURRENCY = 8;

/** Which fan-out a bound was tripped in. Carried into the failure message. */
export type CollectorPipeline = "attribute" | "rule";

/**
 * Bounds on a pipeline's collector fan-out. Every field is optional and falls
 * back to the shipped default, so a pipeline constructed with nothing is still
 * bounded — a library consumer does not opt into being fail-closed.
 *
 * A deployment sets these through `verify.collectorTimeoutMs`,
 * `verify.collectorDeadlineMs` and `verify.collectorConcurrency`; the server
 * package holds those to the same bound at both of its config boundaries (see
 * AGENTS.md, "Two-Boundary Config Validation") and hands the resolved numbers
 * here.
 */
export interface CollectorLimits {
	/** Milliseconds one collector may take. Defaults to {@link DEFAULT_COLLECTOR_TIMEOUT_MS}. */
	collectorTimeoutMs?: number;
	/** Milliseconds the whole fan-out may take. Defaults to {@link DEFAULT_COLLECT_DEADLINE_MS}. */
	deadlineMs?: number;
	/** Collectors in flight at once. Defaults to {@link DEFAULT_COLLECTOR_CONCURRENCY}. */
	concurrency?: number;
}

/** {@link CollectorLimits} with every default filled in. */
export interface ResolvedCollectorLimits {
	collectorTimeoutMs: number;
	deadlineMs: number;
	concurrency: number;
}

/**
 * Fills in the defaults and refuses a limit that is not a positive whole
 * number, naming the field.
 *
 * Refused rather than repaired, and refused at construction rather than at the
 * first request: `concurrency: 0` would otherwise start no collector at all and
 * resolve with an empty result — an empty attribute map and an empty rule set,
 * which is precisely the fail-open this module exists to close. A silently
 * ignored bound is the failure mode #157 catalogued for the config knobs.
 *
 * This check is deliberately *weaker* than the config layer's `resolveBound`
 * rather than a second opinion on the same values: every number `resolveBound`
 * produces for these knobs is a positive integer, so anything accepted there is
 * accepted here. The two cannot reach different verdicts on a configured value
 * — this only catches a hand-written call that never met a config boundary.
 */
export function resolveCollectorLimits(limits?: CollectorLimits): ResolvedCollectorLimits {
	return {
		collectorTimeoutMs: positive(
			limits?.collectorTimeoutMs,
			DEFAULT_COLLECTOR_TIMEOUT_MS,
			"collectorTimeoutMs",
		),
		deadlineMs: positive(limits?.deadlineMs, DEFAULT_COLLECT_DEADLINE_MS, "deadlineMs"),
		concurrency: positive(limits?.concurrency, DEFAULT_COLLECTOR_CONCURRENCY, "concurrency"),
	};
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
 *
 * It never resolves partially: on any failure the results gathered so far are
 * discarded and every sibling still running is cancelled.
 */
export async function runCollectors<T>(
	collectors: readonly Collecting<T>[],
	request: CollectorRequest,
	limits: ResolvedCollectorLimits,
	pipeline: CollectorPipeline,
): Promise<T[]> {
	if (collectors.length === 0) return [];

	// The fan-out's own controller. It aborts for three reasons — the deadline,
	// the caller's signal, or a sibling having already failed the request — and
	// every per-collector signal hangs off it, so any one of them cancels the
	// whole wave.
	const fanOut = new AbortController();
	const deadline = setTimeout(() => {
		fanOut.abort(
			new CollectorTimeoutError({ pipeline, limit: "deadline", timeoutMs: limits.deadlineMs }),
		);
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
			results[index] = await runOne(collectors[index], index, request, limits, pipeline, fanOut);
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
 * The budget starts here, when the collector starts, rather than when the
 * fan-out did: under the concurrency cap a collector waits its turn, and
 * charging it for the queue would refuse work that had not yet begun.
 *
 * A collector whose decision is already lost is **not invoked at all**. Handing
 * one an aborted signal and relying on it to notice is not the same thing: a
 * collector that does not check `signal.aborted` before its first `await` — and
 * most do not, because the honest way to use a signal is to pass it to `fetch`
 * — would have already put the request on the wire. That is an outbound call
 * for an answer nobody will read, made against a dependency that is very often
 * the one whose slowness abandoned the decision in the first place. Refusing to
 * start is the whole point of a concurrency bound; starting and then cancelling
 * only bounds how long the amplification lasts.
 */
async function runOne<T>(
	collector: Collecting<T>,
	index: number,
	request: CollectorRequest,
	limits: ResolvedCollectorLimits,
	pipeline: CollectorPipeline,
	fanOut: AbortController,
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

	const timeout = setTimeout(() => {
		own.abort(
			new CollectorTimeoutError({
				pipeline,
				limit: "collector",
				timeoutMs: limits.collectorTimeoutMs,
				collector: describeCollector(collector, index),
			}),
		);
	}, limits.collectorTimeoutMs);

	const cancelled = rejectOnAbort(own.signal);
	try {
		const context: CollectorContext = { ...request, signal: own.signal };
		// Raced rather than awaited: a collector that ignores its signal — the
		// hung-socket case this is all for — would otherwise never settle, and a
		// bound only the cooperative respect is not a bound.
		return await Promise.race([collector.collect(context), cancelled.promise]);
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
 * **Precondition: `signal` is not yet aborted.** Its one caller creates the
 * controller a few lines above and refuses an already-abandoned fan-out before
 * that, so an already-aborted signal cannot reach here. There is deliberately no
 * defensive branch for it: a listener added to an aborted signal never fires, so
 * such a branch would be the difference between rejecting and hanging — which
 * makes it exactly the kind of code that must be reachable to be trusted, and
 * this one would not be. A future caller that cannot honour the precondition
 * should reject before calling rather than adding an untested path here.
 */
function rejectOnAbort(signal: AbortSignal): { promise: Promise<never>; dispose: () => void } {
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

/**
 * Names a collector the way an operator would look for it: by class, since that
 * is what the config's `collector` key resolves to, with the index as the
 * fallback for a collector wired as an object literal.
 */
function describeCollector(collector: object, index: number): string {
	const name = collector.constructor?.name;
	return name && name !== "Object" ? `${name} (index ${index})` : `at index ${index}`;
}
