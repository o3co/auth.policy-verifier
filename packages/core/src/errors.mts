// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The error classes core defines and a host tells apart: a refused resource
 * string (raised by a `ResourceParser`, e.g. builtins'
 * `DotNotationResourceParser`), a collector fan-out that tripped a bound,
 * conflicting attribute writes, and an asynchronous rule that overran its
 * deadline.
 */

/**
 * Raised by a {@link ResourceParser} when the resource string does not belong
 * to the syntax it parses.
 *
 * A parser refuses rather than guesses: the derived `resourceType` is what
 * scope rules authorize, so a parser that silently repairs its input can make
 * distinct resources collide and hand a caller a grant written for a
 * different resource. Refused, it is a malformed request rather than a wrong
 * decision.
 *
 * This is a **request** error, not a server error: the transport layer should
 * answer it as a 400-class response naming the offending string.
 */
export class ResourceParseError extends Error {
	constructor(
		/** The resource string that was refused, verbatim. */
		readonly raw: string,
		/** Why it was refused, phrased for the caller who sent it. */
		readonly detail: string,
	) {
		super(`Invalid resource string "${raw}": ${detail}`);
		this.name = "ResourceParseError";
	}
}

/** Which bound tripped: one collector's own budget, or the whole fan-out's. */
export type CollectorTimeoutLimit = "collector" | "deadline";

/**
 * What tripped, where, and against which bound.
 *
 * A union rather than one shape with an optional `collector`, because the two
 * limits genuinely carry different information: a per-collector timeout always
 * knows which collector overran, and a deadline never does — it is the *set*
 * that ran out, and no one collector is answerable for it. Stating that in the
 * type is what lets the message be built without a "(unnamed)" fallback for a
 * state the pipeline cannot produce.
 */
export type CollectorTimeoutDetail =
	| {
			/** The fan-out it happened in — `"attribute"` or `"rule"`. */
			pipeline: "attribute" | "rule";
			limit: "collector";
			/** The bound that was exceeded, in milliseconds. */
			timeoutMs: number;
			/**
			 * The collector that overran. Always known for this limit, and spelled
			 * as a `FailureRecord` names a collector that threw:
			 * `attribute.collectors[1] (EntitlementStoreCollector)`.
			 */
			collector: string;
	  }
	| {
			pipeline: "attribute" | "rule";
			limit: "deadline";
			timeoutMs: number;
	  };

/**
 * Raised when a collector fan-out exceeds one of its bounds — a single
 * collector overrunning its own budget, or the pipeline overrunning its
 * end-to-end deadline.
 *
 * **This is a deny, not a degradation.** A distinct class, so a transport can
 * answer it as a deny of its own rather than a generic 500. A pipeline that
 * timed out returns nothing at all: a partial rule list weakens the *policy*,
 * and an empty one is an allow wherever `onEmptyRuleSet: "allow"` is set.
 */
export class CollectorTimeoutError extends Error {
	readonly pipeline: "attribute" | "rule";
	readonly limit: CollectorTimeoutLimit;
	readonly timeoutMs: number;
	readonly collector?: string;

	constructor(detail: CollectorTimeoutDetail) {
		super(
			detail.limit === "collector"
				? `collector ${detail.collector} did not finish within its ${detail.timeoutMs} ms budget`
				: `the ${detail.pipeline} pipeline did not finish within its ${detail.timeoutMs} ms deadline`,
		);
		this.name = "CollectorTimeoutError";
		this.pipeline = detail.pipeline;
		this.limit = detail.limit;
		this.timeoutMs = detail.timeoutMs;
		this.collector = detail.limit === "collector" ? detail.collector : undefined;
	}
}

/**
 * Raised when two attribute maps write **different** values to the same
 * scalar (non-array) key. An identical re-write — same primitive value, or the
 * same object reference — is not a conflict; array-valued keys concatenate.
 *
 * **This is a deny, not a degradation**, as {@link CollectorTimeoutError} is:
 * an attribute map whose content depends on collector ordering is not
 * something to authorize from, and last-writer-wins would silently weaken
 * decisions when collectors disagree.
 *
 * The message names the KEY only, never the values: attribute values are
 * claims and may be sensitive, and this message travels into logs.
 */
export class AttributeConflictError extends Error {
	readonly key: string;

	constructor(key: string) {
		super(
			`two collectors wrote different values to the scalar attribute ${JSON.stringify(key)}; ` +
				"a map whose content depends on collector order is refused. Give the key one " +
				"owning collector, or namespace it (identical re-writes are allowed)",
		);
		this.name = "AttributeConflictError";
		this.key = key;
	}
}

/**
 * Raised by `evaluate()` when an `AsyncRule` does not answer within its
 * budget. **A deny, not a degradation**, for the reason
 * {@link CollectorTimeoutError} is: a rule that has not answered has not
 * passed, and there is no partial answer to an authorization question.
 *
 * Names the rule by `ruleType` and `code` — the two things an operator can find
 * it by in config — and never carries the attributes. `limit` says which bound
 * tripped: the rule's own budget (`"rule"`, `verify.ruleTimeoutMs`), or the
 * deadline for the whole rule phase (`"deadline"`, `verify.evaluateDeadlineMs`),
 * in which case the rule named is the one that was in flight — or, with
 * `started: false`, the next one, which the spent phase never started.
 */
export class RuleTimeoutError extends Error {
	readonly ruleType: string;
	readonly code: string;
	readonly timeoutMs: number;
	readonly limit: "rule" | "deadline";
	/** Whether the named rule had been started; `false` only for a phase spent before it could be. */
	readonly started: boolean;

	constructor(detail: {
		ruleType: string;
		code: string;
		timeoutMs: number;
		limit?: "rule" | "deadline";
		started?: boolean;
	}) {
		const limit = detail.limit ?? "rule";
		const started = detail.started ?? true;
		super(
			limit === "rule"
				? `rule ${detail.ruleType}/${detail.code} did not answer within its ${detail.timeoutMs} ms budget`
				: `the rule phase did not finish within its ${detail.timeoutMs} ms deadline (rule ${detail.ruleType}/${detail.code} was ${started ? "running" : "not started"})`,
		);
		this.started = started;
		this.name = "RuleTimeoutError";
		this.ruleType = detail.ruleType;
		this.code = detail.code;
		this.timeoutMs = detail.timeoutMs;
		this.limit = limit;
	}
}
