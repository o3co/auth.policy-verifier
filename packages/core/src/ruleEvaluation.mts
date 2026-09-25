// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * One invocation of a rule: the reporter it is handed, and the reading of what
 * came back (#244).
 *
 * A rule is third-party code, and what it reports is copied onto the decision
 * — and from there onto the wire and into the audit log — so this is a trust
 * boundary, held the way the failure lines hold a rule's `ruleType` and `code`
 * to an identifier shape (#200). What does not read is refused with a
 * `TypeError` rather than trimmed to what did: dropping a malformed evaluation
 * would record the decision as having reported none, and a wrong audit record
 * that looks complete is worse than a loud fault.
 *
 * No message written here repeats the value it refuses. The error is logged,
 * and the value is whatever the rule put there — policy text and paths
 * included. An error the report's own accessor threw is not one of these: it
 * is the rule's, and like anything else a rule throws it comes back unchanged
 * — the same object, so its class and message are its author's.
 *
 * Everything is read ONCE, into locals, and what is kept is rebuilt from those
 * locals: an object whose properties answer differently the second time — an
 * accessor, a Proxy — is judged on the one reading it got.
 */

import {
	DETERMINING_POLICIES_MAX,
	type DeterminingPolicies,
	POLICY_ID_MAX_LENGTH,
	POLICY_REVISION_MAX_LENGTH,
	POLICY_REVISION_PATTERN,
	type ReportRuleEvaluation,
	type RuleEvaluation,
} from "./types.mjs";

/** How one rule came out: whether it passed, and the evaluation to carry, frozen. */
export interface RuleResult {
	passed: boolean;
	evaluation?: RuleEvaluation;
}

/**
 * The evaluator's side of one invocation. `report` goes to the rule;
 * `conclude` reads the rule's answer together with what it reported; `close`
 * ends the invocation, after which `report` does nothing.
 */
export interface RuleInvocation {
	readonly report: ReportRuleEvaluation;
	/**
	 * @throws {TypeError} for an answer that is not a boolean, for a report that
	 *   was refused (even if the rule caught the refusal), and for a pass that
	 *   reports its evaluator `failed` or `not_invoked`.
	 * @throws whatever an accessor on the report threw, unchanged — likewise even
	 *   if the rule caught it. The caller attributes either to the rule.
	 */
	conclude(answer: unknown): RuleResult;
	close(): void;
}

const STATUSES: ReadonlySet<string> = new Set(["completed", "failed", "not_invoked"]);
const NOT_INVOKED_KEYS: ReadonlySet<string> = new Set(["status"]);
const FAILED_KEYS: ReadonlySet<string> = new Set(["status", "revision", "loadedRevision"]);
const COMPLETED_KEYS: ReadonlySet<string> = new Set([
	...FAILED_KEYS,
	"determiningPolicies",
	"determiningPoliciesOmitted",
]);

/** Whether `value` holds a control character — C0, DEL or C1 — which would let an id forge a log line. */
function hasControlCharacter(value: string): boolean {
	for (let index = 0; index < value.length; index++) {
		const code = value.charCodeAt(index);
		if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
	}
	return false;
}

/**
 * Begins one invocation. Made per call by `evaluate()`, never shared: what a
 * rule reports through it can reach this invocation's outcome and nothing
 * else, which is what keeps concurrent decisions — asked of one rule object —
 * out of each other's records.
 */
export function beginRuleInvocation(): RuleInvocation {
	let reported: RuleEvaluation | undefined;
	// Boxed, because what is kept may be anything a rule's accessor threw.
	let refusal: { readonly error: unknown } | undefined;
	let closed = false;

	const refuse = (error: unknown): never => {
		// Kept as well as thrown: the rule may catch it, and a decision must not
		// come out looking as if nothing had been reported. The first one wins.
		refusal ??= { error };
		throw refusal.error;
	};

	return {
		report(evaluation) {
			// After the answer the decision is made. Not a throw: it would land in
			// the rule's own detached code, as an unhandled rejection.
			if (closed) return;
			if (reported !== undefined || refusal !== undefined) {
				refuse(new TypeError("a rule reported its evaluation more than once for one invocation"));
			}
			try {
				reported = readEvaluation(evaluation);
			} catch (cause) {
				// Either this module's own TypeError, or whatever an accessor on the
				// report threw. Both are kept as they are — see the header comment.
				refuse(cause);
			}
		},

		conclude(answer) {
			closed = true;
			if (refusal !== undefined) throw refusal.error;
			if (typeof answer !== "boolean") {
				// Read by truthiness, this was fail-open for a rule authored in
				// JavaScript — `verify: (attrs) => attrs.get("role")` passed whenever
				// the attribute was set — and carried that value onto the wire as
				// `passed`. The kind of value is named, never the value.
				throw new TypeError(
					`a rule must answer a boolean, got ${answer === null ? "null" : typeof answer}`,
				);
			}
			if (answer && reported !== undefined && reported.status !== "completed") {
				// `failed` and `not_invoked` mean the rule failed closed. A pass that
				// reports either has decided without its policies or reported
				// wrongly, and the record cannot say which.
				throw new TypeError(
					`a rule passed while reporting its evaluation "${reported.status}" — only a completed evaluation can stand behind a pass`,
				);
			}
			return reported === undefined ? { passed: answer } : { passed: answer, evaluation: reported };
		},

		close() {
			closed = true;
		},
	};
}

function readEvaluation(value: unknown): RuleEvaluation {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new TypeError("a rule's evaluation must be an object");
	}
	const keys = Object.keys(value);
	const { status, revision, loadedRevision, determiningPolicies, determiningPoliciesOmitted } =
		value as Record<string, unknown>;
	if (typeof status !== "string" || !STATUSES.has(status)) {
		throw new TypeError(`a rule's evaluation.status must be one of ${[...STATUSES].join(", ")}`);
	}

	if (status === "not_invoked") {
		// An evaluator that was never asked evaluated nothing, so there is no
		// revision to claim — not an evaluated one, and not a loaded one either.
		refuseUnknownKeys(keys, NOT_INVOKED_KEYS, 'a "not_invoked" evaluation');
		return Object.freeze({ status });
	}

	// A failed evaluation's answer is the rule failing closed, not the
	// policies', so only a completed one may say which policies determined it.
	refuseUnknownKeys(
		keys,
		status === "completed" ? COMPLETED_KEYS : FAILED_KEYS,
		status === "completed" ? "a rule's evaluation" : 'a "failed" evaluation',
	);
	const evaluated = status as "completed" | "failed";
	const determining = readDeterminingPolicies(determiningPolicies, determiningPoliciesOmitted);
	if (revision === null) {
		if (loadedRevision === undefined) {
			return Object.freeze({ status: evaluated, revision, ...determining }) as RuleEvaluation;
		}
		return Object.freeze({
			status: evaluated,
			revision,
			loadedRevision: readRevision(loadedRevision, "loadedRevision"),
			...determining,
		}) as RuleEvaluation;
	}
	if (revision === undefined) {
		// Present-and-null is the explicit unknown; absent is a rule that forgot.
		throw new TypeError(
			`a "${evaluated}" evaluation must name its revision, or null when it cannot be established`,
		);
	}
	if (loadedRevision !== undefined) {
		throw new TypeError("a rule's evaluation carries loadedRevision only when revision is null");
	}
	return Object.freeze({
		status: evaluated,
		revision: readRevision(revision, "revision"),
		...determining,
	}) as RuleEvaluation;
}

/**
 * The determining policies of a completed evaluation (#199), copied and
 * frozen, or nothing when the rule named none. The list is read once, by
 * index, so a list whose length or entries answer differently the second time
 * is judged on the one reading.
 */
function readDeterminingPolicies(list: unknown, omitted: unknown): DeterminingPolicies {
	if (list === undefined) {
		if (omitted !== undefined) {
			throw new TypeError(
				"a rule's evaluation carries determiningPoliciesOmitted only beside determiningPolicies",
			);
		}
		return {};
	}
	if (!Array.isArray(list)) {
		throw new TypeError("a rule's evaluation.determiningPolicies must be a list of policy ids");
	}
	const length = list.length;
	if (length > DETERMINING_POLICIES_MAX) {
		throw new TypeError(
			`a rule's evaluation.determiningPolicies lists at most ${DETERMINING_POLICIES_MAX} ids — count the rest in determiningPoliciesOmitted`,
		);
	}
	const ids: string[] = [];
	const seen = new Set<string>();
	for (let index = 0; index < length; index++) {
		const id: unknown = list[index];
		if (
			typeof id !== "string" ||
			id.length === 0 ||
			id.length > POLICY_ID_MAX_LENGTH ||
			hasControlCharacter(id)
		) {
			throw new TypeError(
				`a rule's evaluation.determiningPolicies holds an id that is not 1 to ${POLICY_ID_MAX_LENGTH} characters without a control character`,
			);
		}
		if (seen.has(id)) {
			throw new TypeError(
				"a rule's evaluation.determiningPolicies names a policy twice — it is a set",
			);
		}
		seen.add(id);
		ids.push(id);
	}
	const kept: { determiningPolicies: readonly string[]; determiningPoliciesOmitted?: number } = {
		determiningPolicies: Object.freeze(ids),
	};
	if (omitted !== undefined) {
		if (typeof omitted !== "number" || !Number.isSafeInteger(omitted) || omitted < 1) {
			throw new TypeError(
				"a rule's evaluation.determiningPoliciesOmitted must be a positive whole number — absent when nothing was omitted",
			);
		}
		kept.determiningPoliciesOmitted = omitted;
	}
	return kept;
}

function readRevision(value: unknown, key: string): string {
	if (
		typeof value !== "string" ||
		value.length > POLICY_REVISION_MAX_LENGTH ||
		!POLICY_REVISION_PATTERN.test(value)
	) {
		throw new TypeError(
			`a rule's evaluation.${key} must be a policy revision reference — scheme:encoded, at most ${POLICY_REVISION_MAX_LENGTH} characters`,
		);
	}
	return value;
}

function refuseUnknownKeys(
	keys: readonly string[],
	allowed: ReadonlySet<string>,
	what: string,
): void {
	const unknown = keys.filter((key) => !allowed.has(key));
	if (unknown.length > 0) {
		// The count, not the names: a key is as much the rule's text as a value is.
		throw new TypeError(
			`${what} carries ${unknown.length} key(s) the contract does not name (allowed: ${[...allowed].join(", ")})`,
		);
	}
}
