// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * What kind of failure kept a decision from being made, and where (#200).
 *
 * `verify_internal_error` used to carry the error and the endpoint, nothing
 * else — so "which fact source is failing?" was a regex over `err.message`, and
 * a dashboard could not point at one misbehaving collector at all. This module
 * is the one place a failure is sorted: every failure line the verify router
 * emits for a decision it could not make carries the category it returns, and
 * the collector counter is labelled with it.
 */

import {
	AttributeConflictError,
	CollectorTimeoutError,
	type FailureRecord,
	type FailureSource,
	RuleTimeoutError,
} from "@o3co/auth.policy-verifier.core";
import type { NamedRule } from "./decisionEvent.mjs";

/**
 * Every value `category` can take, in one closed set — so the log line and the
 * counter label can be filtered by equality, and a dashboard written against
 * them is written against everything there is.
 *
 * - `collector_timeout` — a collector overran `collectorTimeoutMs`, or its
 *   pipeline overran `collectorDeadlineMs`. Answered `403 collector_timeout`.
 * - `collector_threw` — a collector rejected or threw. Answered `500`.
 * - `attribute_conflict` — two attribute collectors wrote different values to
 *   one scalar key. Answered `403 attribute_conflict`; no one collector is
 *   answerable, so none is named.
 * - `rule_timeout` — an asynchronous rule overran `ruleTimeoutMs`, or the rule
 *   phase overran `evaluateDeadlineMs`. Answered `403 rule_timeout`.
 * - `rule_threw` — a rule's `verify` threw or its `decide` rejected. Answered
 *   `500`.
 * - `body_rejected` — the JSON body parser failed in a way the deny envelope
 *   does not map to a 4xx (a stream something upstream already read or set an
 *   encoding on, a length mismatch). Answered `500`.
 * - `internal` — anything that did not come out of a decision's own collect
 *   or evaluation: a resource parser or authenticator that threw, whatever
 *   class it threw. Answered `500`.
 *
 * **Not a category: an unreachable JWKS.** The built-in authenticator answers
 * it `401 invalid_token` and logs `jwt_verification_unavailable` at error; it
 * never reaches a line this set labels, and a value no line can carry would
 * be a filter that never matches.
 */
export const FAILURE_CATEGORIES = [
	"collector_timeout",
	"collector_threw",
	"attribute_conflict",
	"rule_timeout",
	"rule_threw",
	"body_rejected",
	"internal",
] as const;

export type FailureCategory = (typeof FAILURE_CATEGORIES)[number];

/** The categories `auth_collector_failures_total` counts: the ones a collector is answerable for. */
export type CollectorFailureCategory = Extract<
	FailureCategory,
	"collector_timeout" | "collector_threw"
>;

/**
 * The collector named when a failure's class says "collector timeout" but no
 * collector runner recorded it — a rule that rejected with one, or a pipeline
 * that does not keep a `FailureRecord`. `CollectorTimeoutError` is a public
 * class, and the name inside one somebody else built is not read.
 */
export const UNATTRIBUTED = "unattributed";

/** What a rule's `ruleType` or `code`, or an attribute key, is logged as when it is not identifier-shaped. */
export const REDACTED = "redacted";

/**
 * The shape a rule's `ruleType` and `code` — and an attribute key — must have to
 * be logged: a letter, then letters, digits, `_`, `.` or `-`, at most 64
 * characters in all. Codes are documented as short stable identifiers
 * (`invalid_scope`, `cedar_deny`) and keys as the deployment's own constants,
 * but a collector builds rules and attribute maps per request and may derive
 * either from the claims or the context; anything carrying whitespace, `@`,
 * `:`, a line break, or the length of a token is not an identifier an operator
 * wrote.
 */
const IDENTIFIER = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;

const identifier = (value: unknown): string =>
	typeof value === "string" && IDENTIFIER.test(value) ? value : REDACTED;

/**
 * A failure, sorted. The collector or rule is named exactly when the category
 * has one to name, which the union states rather than leaving to optional
 * fields.
 *
 * Nothing here is read off the error or from the request: the category is from
 * the set above, the collector or rule is what the runner or the evaluator
 * recorded — or {@link UNATTRIBUTED} — and a rule's identity passes the
 * identifier shape or is {@link REDACTED}.
 */
export type ClassifiedFailure =
	| {
			category: CollectorFailureCategory;
			/**
			 * `attribute.collectors[1] (EntitlementStoreCollector)` — or, for a
			 * pipeline deadline, the list itself (`attribute.collectors`): the set
			 * ran out, and no one entry of it is answerable.
			 */
			collector: string;
	  }
	| { category: "rule_timeout" | "rule_threw"; rule: NamedRule }
	| { category: "attribute_conflict" | "body_rejected" | "internal" };

/**
 * Sorts what one decision's collect or evaluation failed with, reading where
 * it came from out of that decision's own `failures`.
 *
 * The three deny errors are recognised by class first, exactly as the router
 * recognises them to answer a deny: a collector that rethrows a nested
 * pipeline's `CollectorTimeoutError` is still a timeout. What the class does
 * **not** decide is the name — that is always the record's, so a collector
 * cannot log or label itself as anything but its own position by throwing a
 * timeout it built.
 *
 * Only for failures out of a decision: a fault anywhere else is `internal`,
 * and `body_rejected` is the router's terminal handler's to decide.
 */
export function classifyFailure(cause: unknown, failures?: FailureRecord): ClassifiedFailure {
	const source = failures?.sourceOf(cause);
	if (cause instanceof CollectorTimeoutError) {
		return { category: "collector_timeout", collector: collectorName(source) };
	}
	if (cause instanceof RuleTimeoutError) {
		return { category: "rule_timeout", rule: ruleName(source) };
	}
	if (cause instanceof AttributeConflictError) {
		return { category: "attribute_conflict" };
	}
	if (source?.kind === "collector") {
		return { category: "collector_threw", collector: source.collector };
	}
	if (source?.kind === "rule") {
		return { category: "rule_threw", rule: ruleName(source) };
	}
	return { category: "internal" };
}

/**
 * The error to log as `err` for a failure: the one thrown, except for the three
 * deny errors core defines, which are rebuilt from safe parts.
 *
 * Those three name what they are about in their message **and** in their own
 * fields — `RuleTimeoutError.ruleType` / `.code`, `CollectorTimeoutError.collector`,
 * `AttributeConflictError.key` — and a JSON logger serialises both (pino's `err`
 * serializer copies every enumerable property). Each is text a collector can
 * derive from the claims or the context, or put into an instance it built
 * itself. So what is logged is a fresh instance of the same class: the rule or
 * collector the classification named (never the error's), an attribute key
 * held to the identifier shape, and the numeric and enum fields only when they
 * are what their types say. Its `stack` is the header line alone: the original
 * stack begins with the original message, and the frames of the rebuilt one
 * would be the log site's.
 *
 * Logging only — what was thrown, and what `instanceof` routed on, is untouched.
 * Every other error is handed back as thrown: its message is its author's.
 */
export function loggableError(cause: unknown, failure: ClassifiedFailure): unknown {
	if (cause instanceof RuleTimeoutError) {
		const rule = "rule" in failure ? failure.rule : { ruleType: UNATTRIBUTED, code: UNATTRIBUTED };
		return headerOnly(
			new RuleTimeoutError({
				ruleType: rule.ruleType,
				code: rule.code,
				timeoutMs: milliseconds(cause.timeoutMs),
				limit: cause.limit === "deadline" ? "deadline" : "rule",
				started: cause.started !== false,
			}),
		);
	}
	if (cause instanceof CollectorTimeoutError) {
		const pipeline = cause.pipeline === "rule" ? "rule" : "attribute";
		const timeoutMs = milliseconds(cause.timeoutMs);
		return headerOnly(
			cause.limit === "deadline"
				? new CollectorTimeoutError({ pipeline, limit: "deadline", timeoutMs })
				: new CollectorTimeoutError({
						pipeline,
						limit: "collector",
						timeoutMs,
						collector: "collector" in failure ? failure.collector : UNATTRIBUTED,
					}),
		);
	}
	if (cause instanceof AttributeConflictError) {
		return headerOnly(new AttributeConflictError(identifier(cause.key)));
	}
	return cause;
}

/** A budget as logged: the number it should be, or `0` for anything else. */
const milliseconds = (value: unknown): number =>
	typeof value === "number" && Number.isFinite(value) ? value : 0;

/** Replaces a rebuilt error's stack with its header line — see {@link loggableError}. */
function headerOnly<E extends Error>(error: E): E {
	error.stack = `${error.name}: ${error.message}`;
	return error;
}

/** The collector a recorded source names: one entry, a pipeline's whole list, or nobody. */
function collectorName(source: FailureSource | undefined): string {
	if (source?.kind === "collector") return source.collector;
	if (source?.kind === "deadline") return `${source.pipeline}.collectors`;
	return UNATTRIBUTED;
}

/** The rule a recorded source names, each part held to the identifier shape. */
function ruleName(source: FailureSource | undefined): NamedRule {
	return source?.kind === "rule"
		? { ruleType: identifier(source.ruleType), code: identifier(source.code) }
		: { ruleType: UNATTRIBUTED, code: UNATTRIBUTED };
}
