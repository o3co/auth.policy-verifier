// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Raised by a {@link ResourceParser} when the resource string does not belong
 * to the syntax it parses.
 *
 * A parser that cannot read its input has two options: guess, or refuse.
 * Guessing is what makes distinct resources collide into one authorization
 * namespace — the derived `resourceType` is what scope rules authorize, so a
 * parser that silently repairs its input can hand a caller a grant that was
 * written for a different resource. Refusing keeps the failure at the edge,
 * where it is a malformed request rather than a wrong decision.
 *
 * This is a **request** error, not a server error: the transport layer should
 * answer it as a 400-class response naming the offending string, the same as
 * any other unusable field of the request body.
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
			/** The collector that overran. Always known for this limit. */
			collector: string;
	  }
	| {
			pipeline: "attribute" | "rule";
			limit: "deadline";
			timeoutMs: number;
	  };

/**
 * Raised when a collector fan-out exceeds one of its bounds (#115) — a single
 * collector overrunning its own budget, or the pipeline overrunning its
 * end-to-end deadline.
 *
 * **This is a deny, not a degradation.** It exists as a distinct error class so
 * a transport can answer it as a deny of its own rather than letting it fall
 * into a generic 500, and so the collectors that were quick cannot be mistaken
 * for the whole answer: a pipeline that timed out returns nothing at all. A
 * partial attribute map merely weakens a rule's inputs, but a partial rule list
 * weakens the *policy* — and an empty one is an allow wherever
 * `onEmptyRuleSet: "allow"` is set. There is no shape of "answer with what we
 * got" that is safe on an authorization path, which is why this is thrown
 * instead.
 */
export class CollectorTimeoutError extends Error {
	readonly pipeline: "attribute" | "rule";
	readonly limit: CollectorTimeoutLimit;
	readonly timeoutMs: number;
	readonly collector?: string;

	constructor(detail: CollectorTimeoutDetail) {
		super(
			detail.limit === "collector"
				? `${detail.pipeline} collector ${detail.collector} did not finish within its ${detail.timeoutMs} ms budget`
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
 * scalar (non-array) key (#174). An identical re-write — same primitive
 * value, or the same object reference — is not a conflict.
 *
 * **This is a deny, not a degradation** — the same stance as
 * {@link CollectorTimeoutError}: an attribute map whose content depends on
 * collector ordering is not something to authorize from, and the previous
 * last-writer-wins silently weakened decisions when collectors disagreed
 * (#126 item 2). Array-valued keys are unaffected; they concatenate.
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
