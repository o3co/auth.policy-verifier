// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { preparsePolicySet, statefulIsAuthorized } from "@cedar-policy/cedar-wasm/nodejs";
import type {
	CollectorContext,
	Logger,
	Rule,
	RuleCollector,
} from "@o3co/auth.policy-verifier.core";
import { createConsoleLogger } from "@o3co/auth.policy-verifier.core";
import {
	buildCedarRequest,
	type CedarRequest,
	type ResolvedMapping,
	resolveMapping,
} from "./mapping.mjs";
import { loadPolicySource } from "./policySource.mjs";

/** What the rule answers when no policy determined the request (see below). */
export type NoDeterminingPolicy = "abstain" | "deny";

const NO_DETERMINING_POLICIES: readonly NoDeterminingPolicy[] = ["abstain", "deny"];

/** Config entry accepted by `CedarPolicyRuleCollector`. */
export interface CedarPolicyRuleCollectorConfig {
	/** Directory of `*.cedar` files (sorted, concatenated). XOR `policies`. */
	policyDir?: string;
	/** Inline Cedar policy text. XOR `policyDir`. */
	policies?: string;
	/** Rule group the Cedar decision joins AND-evaluation as. Default `"cedar"`. */
	ruleType?: string;
	/**
	 * What the rule answers when Cedar reports no determining policy — no
	 * `permit` matched and no `forbid` matched.
	 *
	 * `"abstain"` (default) passes the group, leaving the decision to the other
	 * rule groups: the migration posture, where the policy set covers part of
	 * the surface and the TypeScript rules still hold the rest. `"deny"` makes
	 * the policy set authoritative — Cedar's own implicit-deny — for the moment
	 * it covers everything.
	 */
	onNoDeterminingPolicy?: NoDeterminingPolicy;
	/**
	 * Whether the rule logs Cedar evaluation errors (default `true`).
	 *
	 * The error branch is load-bearing: Cedar answers a policy that reads a
	 * missing attribute with `decision: "deny"` and the cause only in
	 * `diagnostics.errors` — without this log, a typo'd attribute mapping is
	 * indistinguishable from a policy deny. The healthy path never logs.
	 */
	logEvaluationErrors?: boolean;
	/** Entity/context mapping — see `resolveMapping` for the shape. */
	principal?: unknown;
	action?: unknown;
	resource?: unknown;
	context?: unknown;
}

/** Constructor options beyond the config entry (programmatic composition only). */
export interface CedarPolicyRuleCollectorOptions {
	/** Receives evaluation-error logs. Defaults to the console-backed logger. */
	logger?: Logger;
}

/** Distinguishes concurrently-constructed collectors' preparsed sets. */
let policySetCounter = 0;

/**
 * Evaluates a Cedar policy set, co-resident, as one core `Rule`.
 *
 * ## Why one rule, not a translation
 *
 * Core's evaluator is OR within a group and AND across groups, with no global
 * override; Cedar's forbid-overrides-permit is inexpressible in that algebra.
 * So the policy set is never translated into core rules — the real Cedar
 * evaluator runs, and its whole verdict enters AND-evaluation as a single
 * group. Layered PDP: Cedar semantics inside the group, core semantics across
 * groups, composing only toward strictness.
 *
 * ## Why evaluation happens in `verify`
 *
 * The attribute and rule pipelines run concurrently, so `collect` never sees
 * the merged attributes — and the point of the design is that Cedar policies
 * decide over what the attribute collectors gathered. `verify(attrs)` is where
 * that map exists. Cedar evaluation is a deterministic, synchronous function
 * of `(preparsed policy set, request)` with the request built from `attrs`
 * alone, so the rule satisfies the purity contract exactly: the policy set id
 * and mapping are fixed at boot, nothing of `CollectorContext` is retained,
 * and equal attributes give equal answers. The rule object is built once, in
 * the constructor — the hoisted form `metrics.test.mts` documents as the
 * strongest compliance shape.
 *
 * The one deliberate softening: on the *error* branch the rule emits a log
 * line (config `logEvaluationErrors`, default on). The decision itself remains
 * a pure function of `attrs`; see the config doc for why silence there would
 * cost more than the letter of "no side effects" buys.
 *
 * ## Answer interpretation
 *
 * | Cedar answered | with | the rule answers |
 * | --- | --- | --- |
 * | `allow` | no errors | pass |
 * | `deny` | determining `forbid` | fail |
 * | `deny` | no determining policy | `onNoDeterminingPolicy` |
 * | anything | evaluation errors | **fail, and log** |
 *
 * The last row is unconditional — an evaluation error is never an abstention.
 * Cedar treats a policy that errors as not satisfied, so a `forbid` that
 * errors stops forbidding and the top-level decision can read `allow`; the
 * errors check runs first precisely so that a broken input fails closed.
 */
export class CedarPolicyRuleCollector implements RuleCollector {
	private readonly rule: Rule;

	constructor(config: CedarPolicyRuleCollectorConfig, options?: CedarPolicyRuleCollectorOptions) {
		const raw = (config ?? {}) as Record<string, unknown>;

		const ruleType = raw.ruleType === undefined ? "cedar" : raw.ruleType;
		if (typeof ruleType !== "string" || ruleType.length === 0) {
			throw new Error(
				`CedarPolicyRuleCollector: ruleType must be a non-empty string, got ${JSON.stringify(raw.ruleType)}`,
			);
		}

		const onNoDeterminingPolicy = (raw.onNoDeterminingPolicy ?? "abstain") as NoDeterminingPolicy;
		if (!NO_DETERMINING_POLICIES.includes(onNoDeterminingPolicy)) {
			throw new Error(
				`CedarPolicyRuleCollector: onNoDeterminingPolicy must be one of ${NO_DETERMINING_POLICIES.join(", ")}, got ${JSON.stringify(raw.onNoDeterminingPolicy)}`,
			);
		}

		const rawLog = raw.logEvaluationErrors;
		if (rawLog !== undefined && typeof rawLog !== "boolean") {
			throw new Error(
				`CedarPolicyRuleCollector: logEvaluationErrors must be a boolean, got ${JSON.stringify(rawLog)}`,
			);
		}
		const logEvaluationErrors = rawLog ?? true;

		const mapping: ResolvedMapping = resolveMapping(raw);
		const source = loadPolicySource(raw);

		// Boot-time compile. `preparsePolicySet` stores the compiled set in wasm
		// memory under this id; the per-request call references it without
		// re-parsing. The id is per-instance so two collectors never share a slot.
		const policySetId = `auth.policy-verifier.cedar:${policySetCounter++}`;
		const parsed = preparsePolicySet(policySetId, { staticPolicies: source.text });
		if (parsed.type === "failure") {
			const details = parsed.errors.map((error) => error.message).join("; ");
			throw new Error(
				`CedarPolicyRuleCollector: policy set from ${source.description} failed to compile: ${details}`,
			);
		}

		const logger = logEvaluationErrors
			? (options?.logger ?? createConsoleLogger({ collector: "CedarPolicyRuleCollector" }))
			: undefined;

		this.rule = buildRule({ ruleType, onNoDeterminingPolicy, policySetId, mapping, logger });
	}

	async collect(_context: CollectorContext): Promise<Rule[]> {
		// Nothing is read from the context: everything the rule needs was fixed
		// at boot, and everything request-shaped reaches it through `attrs`.
		return [this.rule];
	}
}

function buildRule(bound: {
	ruleType: string;
	onNoDeterminingPolicy: NoDeterminingPolicy;
	policySetId: string;
	mapping: ResolvedMapping;
	logger: Logger | undefined;
}): Rule {
	const { ruleType, onNoDeterminingPolicy, policySetId, mapping, logger } = bound;
	return {
		ruleType,
		code: "cedar_deny",
		message: "Denied by Cedar policy",
		verify(attrs) {
			let request: CedarRequest;
			try {
				request = buildCedarRequest(mapping, attrs);
			} catch (cause) {
				logger?.error(
					{ policySetId, reason: cause instanceof Error ? cause.message : String(cause) },
					"cedar request could not be built from attributes — denying",
				);
				return false;
			}

			const answer = statefulIsAuthorized({ ...request, preparsedPolicySetId: policySetId });
			if (answer.type !== "success") {
				logger?.error(
					{ policySetId, errors: answer.errors.map((error) => error.message) },
					"cedar authorization call failed — denying",
				);
				return false;
			}

			const { decision, diagnostics } = answer.response;
			if (diagnostics.errors.length > 0) {
				// Checked before the decision on purpose: an erroring `forbid` stops
				// forbidding, so `decision` can read "allow" exactly when it is least
				// trustworthy. Never an abstention.
				logger?.error(
					{
						policySetId,
						decision,
						errors: diagnostics.errors.map((error) => `${error.policyId}: ${error.error.message}`),
					},
					"cedar policy evaluation raised errors — denying",
				);
				return false;
			}

			if (decision === "allow") return true;
			if (diagnostics.reason.length === 0) return onNoDeterminingPolicy === "abstain";
			return false;
		},
	};
}
