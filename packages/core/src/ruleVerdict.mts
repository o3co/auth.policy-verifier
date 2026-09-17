// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Reading what a rule answered (#244).
 *
 * A rule is third-party code, and since a verdict's `evaluation` is copied
 * onto the decision — and from there onto the wire and into the audit log —
 * this is a trust boundary, held the way the failure lines hold a rule's
 * `ruleType` and `code` to an identifier shape (#200). A verdict that does not
 * read is refused with a `TypeError` rather than trimmed to what did: dropping
 * a malformed evaluation would record a decision as having reported none, and
 * a wrong audit record that looks complete is worse than a loud fault.
 *
 * No message here repeats the value it refuses. The error is logged, and the
 * value is whatever the rule put there — policy text and paths included.
 */

import {
	POLICY_REVISION_MAX_LENGTH,
	POLICY_REVISION_PATTERN,
	type RuleAnswer,
	type RuleEvaluation,
} from "./types.mjs";

/** A rule's answer, read: whether it passed, and the evaluation to carry, frozen. */
export interface ReadRuleAnswer {
	passed: boolean;
	evaluation?: RuleEvaluation;
}

const VERDICT_KEYS: ReadonlySet<string> = new Set(["passed", "evaluation"]);
const STATUSES: ReadonlySet<string> = new Set(["completed", "failed", "not_invoked"]);
const NOT_INVOKED_KEYS: ReadonlySet<string> = new Set(["status"]);
const EVALUATED_KEYS: ReadonlySet<string> = new Set(["status", "revision", "loadedRevision"]);

/**
 * Reads what `verify` / `decide` returned.
 *
 * A boolean — anything that is not an object, for a JavaScript rule — is the
 * answer it always was. An object is a `RuleVerdict` and is checked whole:
 * `passed` a boolean, `evaluation` absent or one of the three shapes
 * `RuleEvaluation` allows, no key beyond those.
 *
 * @throws {TypeError} for a verdict that is not one; the caller attributes it
 *   to the rule.
 */
export function readRuleAnswer(answer: RuleAnswer): ReadRuleAnswer {
	if (typeof answer !== "object" || answer === null) return { passed: answer };

	const verdict = answer as unknown as Record<string, unknown>;
	refuseUnknownKeys(verdict, VERDICT_KEYS, "a rule verdict");
	if (typeof verdict.passed !== "boolean") {
		throw new TypeError("a rule verdict needs a boolean passed");
	}
	if (verdict.evaluation === undefined) return { passed: verdict.passed };
	return { passed: verdict.passed, evaluation: readEvaluation(verdict.evaluation) };
}

function readEvaluation(value: unknown): RuleEvaluation {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new TypeError("a rule verdict's evaluation must be an object");
	}
	const evaluation = value as Record<string, unknown>;
	const { status } = evaluation;
	if (typeof status !== "string" || !STATUSES.has(status)) {
		throw new TypeError(
			`a rule verdict's evaluation.status must be one of ${[...STATUSES].join(", ")}`,
		);
	}

	if (status === "not_invoked") {
		// An evaluator that was never asked evaluated nothing, so there is no
		// revision to claim — not an evaluated one, and not a loaded one either.
		refuseUnknownKeys(evaluation, NOT_INVOKED_KEYS, 'a "not_invoked" evaluation');
		return Object.freeze({ status });
	}

	refuseUnknownKeys(evaluation, EVALUATED_KEYS, "a rule verdict's evaluation");
	const evaluated = status as "completed" | "failed";
	const { revision, loadedRevision } = evaluation;
	if (revision === null) {
		if (loadedRevision === undefined) return Object.freeze({ status: evaluated, revision });
		return Object.freeze({
			status: evaluated,
			revision,
			loadedRevision: readRevision(loadedRevision, "loadedRevision"),
		});
	}
	if (revision === undefined) {
		// Present-and-null is the explicit unknown; absent is a rule that forgot.
		throw new TypeError(
			`a "${evaluated}" evaluation must name its revision, or null when it cannot be established`,
		);
	}
	if (loadedRevision !== undefined) {
		throw new TypeError(
			"a rule verdict's evaluation carries loadedRevision only when revision is null",
		);
	}
	return Object.freeze({ status: evaluated, revision: readRevision(revision, "revision") });
}

function readRevision(value: unknown, key: string): string {
	if (
		typeof value !== "string" ||
		value.length > POLICY_REVISION_MAX_LENGTH ||
		!POLICY_REVISION_PATTERN.test(value)
	) {
		throw new TypeError(
			`a rule verdict's evaluation.${key} must be a policy revision reference — scheme:encoded, at most ${POLICY_REVISION_MAX_LENGTH} characters`,
		);
	}
	return value;
}

function refuseUnknownKeys(
	object: Record<string, unknown>,
	allowed: ReadonlySet<string>,
	what: string,
): void {
	const unknown = Object.keys(object).filter((key) => !allowed.has(key));
	if (unknown.length > 0) {
		// The count, not the names: a key is as much the rule's text as a value is.
		throw new TypeError(
			`${what} carries ${unknown.length} key(s) the contract does not name (allowed: ${[...allowed].join(", ")})`,
		);
	}
}
