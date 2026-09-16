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
	failureSourceOf,
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
 * - `internal` — anything nothing attributed: a resource parser or
 *   authenticator that threw, a collector that rejected with something other
 *   than an object. Answered `500`.
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
 * A failure, sorted. The collector or rule is named exactly when the category
 * has one to name, which the union states rather than leaving to optional
 * fields.
 *
 * Every field is fixed by configuration — a category from the set above, a
 * collector's position and class, a rule's `ruleType` and `code` — so nothing
 * here was read from the request.
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
 * Sorts whatever kept a decision from being made.
 *
 * The three deny errors are recognised by class first, exactly as the router
 * recognises them to answer a deny: a collector that rethrows a nested
 * pipeline's `CollectorTimeoutError` is still a timeout. Only then is core's
 * attribution consulted. `body_rejected` is not decided here — only the
 * router's terminal handler can tell a body-parser failure from anything else
 * that reached it.
 */
export function classifyFailure(cause: unknown): ClassifiedFailure {
	if (cause instanceof CollectorTimeoutError) {
		return {
			category: "collector_timeout",
			collector: cause.collector ?? `${cause.pipeline}.collectors`,
		};
	}
	if (cause instanceof RuleTimeoutError) {
		return { category: "rule_timeout", rule: { ruleType: cause.ruleType, code: cause.code } };
	}
	if (cause instanceof AttributeConflictError) {
		return { category: "attribute_conflict" };
	}
	const source = failureSourceOf(cause);
	if (source?.kind === "collector") {
		return { category: "collector_threw", collector: source.collector };
	}
	if (source?.kind === "rule") {
		return { category: "rule_threw", rule: { ruleType: source.ruleType, code: source.code } };
	}
	return { category: "internal" };
}
