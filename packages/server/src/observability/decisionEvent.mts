// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The per-decision audit line (#111).
 *
 * An authorization service that cannot answer "why was this request denied?"
 * from its own output is undiagnosable during the incident it is at the centre
 * of. The engine already computes the answer — every `Decision` carries a
 * structured `reason` — and this module projects it onto a flat, structured log
 * record.
 *
 * What is in the record is chosen twice over: once for what an operator needs,
 * and once for what must never leave the process. See {@link decisionEvent}.
 */

import type { Decision, RuleGroupOutcome } from "@o3co/auth.policy-verifier.core";

/**
 * Event name of the audit line. Alert and index on this, not on message text.
 */
export const DECISION_EVENT = "decision";

/** How this engine names one rule: there is no rule id, so `ruleType` + `code` is the identity. */
export interface NamedRule {
	ruleType: string;
	/**
	 * The rule's own `code`. It reads as a denial reason (`invalid_scope`)
	 * because that is what a `Rule` carries for the failing case — but it is the
	 * rule's identifier, so it names the rule on a pass too.
	 */
	code: string;
}

/** The group that refused, and every alternative in it that was tried. */
export interface DenyingGroup {
	ruleType: string;
	/** `code` of every rule in the group, in evaluation order — all of them refused. */
	refused: string[];
}

/** Everything the router knows about one decision at the moment it emits the line. */
export interface DecisionEventInput {
	decision: Decision;
	/** JWT `sub` of the presented token. Absent when the token carries none. */
	subject?: string;
	/** The resource string exactly as the caller sent it. */
	resource: string;
	action: string;
	/** `x-request-id` as sent, when the caller sent one. */
	requestId?: string;
	/** Wall-clock time spent collecting attributes and rules and evaluating them. */
	durationMs: number;
}

/** `satisfiedBy` for a passing group; `undefined` for a group that is not one. */
function satisfyingRule(group: RuleGroupOutcome): NamedRule | undefined {
	// #135 split the outcome: `evaluated` is what ran, `satisfiedBy` is what
	// decided, and it exists only on the pass arm. Reading `evaluated.at(-1)`
	// instead would happen to give the same rule and would silently start
	// naming the wrong one the moment the group semantics change.
	return group.passed ? { ruleType: group.ruleType, code: group.satisfiedBy.code } : undefined;
}

/**
 * Builds the structured fields of one `decision` log line.
 *
 * **Carried:** subject (`sub`), resource, action, the decision, the deny
 * `code`, the deciding rule, the request id, and how long the decision took.
 * That is the set an operator needs to answer "why was this denied" and to
 * join the answer to the caller's own trace.
 *
 * **Deliberately absent**, because this line is written on every request —
 * including the ones that succeed — and shipped somewhere with a different
 * blast radius from the token itself:
 *
 * - the raw bearer token, and the claim set as a whole. Only `sub` crosses,
 *   because only `sub` is the answer to "who". A token may carry `email`, group
 *   membership or anything else the issuer chose to mint, and none of it is
 *   needed to explain a decision.
 * - the caller's `context` object. It is free-form and forwarded verbatim to
 *   collectors, so it is exactly where a calling service's own request payload
 *   ends up; logging it turns the audit stream into a copy of that payload.
 * - rule `message` text. It is derived from the resource and action already on
 *   the line, so it adds length rather than information.
 *
 * The rule name is `ruleType` + `code` rather than free text, which is also
 * what keeps it usable as a metric label — see `observability/metrics.mts`.
 */
export function decisionEvent({
	decision,
	subject,
	resource,
	action,
	requestId,
	durationMs,
}: DecisionEventInput): Record<string, unknown> {
	const event: Record<string, unknown> = {
		// Omitted rather than emitted empty: `sub: ""` in an audit record reads as
		// a subject that exists, and most callers send no request id at all.
		...(requestId !== undefined ? { requestId } : {}),
		...(subject !== undefined ? { sub: subject } : {}),
		resource,
		action,
		decision: decision.decision,
		// Microsecond resolution. A decision is in-process work, so whole
		// milliseconds would round most of them to 0 and lose the tail entirely.
		durationMs: Math.round(durationMs * 1000) / 1000,
	};

	if (decision.decision === "allow") {
		// Every group passed — AND across groups is what an allow means — so each
		// one names the rule that satisfied it. Reporting a single "the" rule
		// would have to pick one arbitrarily. An empty array is the honest answer
		// for a deployment running `onEmptyRuleSet = "allow"`: nothing decided.
		event.satisfiedBy = decision.reason.groups.flatMap((group) => {
			const rule = satisfyingRule(group);
			return rule ? [rule] : [];
		});
		return event;
	}

	event.code = decision.code;
	// The FIRST failing group, matching the `code` on the wire response. A group
	// is an OR, so a failing one ran every alternative and every one refused —
	// which is why `refused` is a list rather than a single rule.
	const failing = decision.reason.groups.find((group) => !group.passed);
	if (failing) {
		event.deniedBy = {
			ruleType: failing.ruleType,
			refused: failing.evaluated.map((outcome) => outcome.code),
		} satisfies DenyingGroup;
	}
	// No failing group means no group ran at all (`no_applicable_rule`). The code
	// is the whole answer; a `deniedBy` here would name a rule that never existed.
	return event;
}
