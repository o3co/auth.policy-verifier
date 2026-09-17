// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * `verify.evaluationInResponse` (#244) — whether the decision response carries
 * what each rule reported about the evaluation behind its answer
 * (`RuleOutcome.evaluation`: its status, and the policy revision).
 *
 * The `decision` event always carries it: the audit log is the operator's own.
 * The response is another matter. It goes to whoever presented a token this
 * deployment accepts, and an evaluation says more about the inside of the PDP
 * than a deny code does — that a policy set changed between two calls, that a
 * denial was the engine failing rather than a policy refusing. OPA
 * (`?provenance=true`) and XACML (`ReturnPolicyIdList`) make the same
 * information opt-in, by the requester; here the opt-in is the deployment's,
 * because what a token holder may learn about the policy layer is not the
 * token holder's to decide. `"omit"` is the default, and with it the response
 * is key-for-key what it was before this existed. #199's determining policy
 * ids will ride the same object and so the same switch.
 *
 * One check, imported by both boundaries (AGENTS.md, "Two-Boundary Config
 * Validation"): `AppConfigSchema` files the refusal as an issue at the key,
 * `createVerifyRouter` throws it. A hand-built config that misspelt `"include"`
 * would otherwise run as `"omit"` without a word, and the consuming service
 * that turned this on in order to record revisions would record none.
 * Dependency-free, so the schema can import it.
 */

/** The accepted values, default first. */
export const EVALUATION_IN_RESPONSE_VALUES = ["omit", "include"] as const;

export type EvaluationInResponse = (typeof EVALUATION_IN_RESPONSE_VALUES)[number];

export const DEFAULT_EVALUATION_IN_RESPONSE: EvaluationInResponse = "omit";

export type EvaluationInResponseCheck =
	| { ok: true; value: EvaluationInResponse }
	| { ok: false; message: string };

/**
 * Reads `verify.evaluationInResponse`. Absent is the default; anything that is
 * not one of {@link EVALUATION_IN_RESPONSE_VALUES} is refused, `null` included —
 * the schema types the key as an optional enum and refuses `null` before this
 * is reached, so reading it here as "unset" would hand a hand-built config a
 * different answer from a parsed one.
 */
export function checkEvaluationInResponse(
	value: unknown,
	path = "verify",
): EvaluationInResponseCheck {
	if (value === undefined) return { ok: true, value: DEFAULT_EVALUATION_IN_RESPONSE };
	if ((EVALUATION_IN_RESPONSE_VALUES as readonly unknown[]).includes(value)) {
		return { ok: true, value: value as EvaluationInResponse };
	}
	return {
		ok: false,
		message: `${path}.evaluationInResponse must be one of ${EVALUATION_IN_RESPONSE_VALUES.join(", ")}, got ${describe(value)}`,
	};
}

function describe(value: unknown): string {
	return typeof value === "string" ? JSON.stringify(value) : String(value);
}
