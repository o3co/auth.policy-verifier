// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	AnyRule,
	AsyncRule,
	CollectorContext,
	Logger,
	ReadonlyAttributes,
	Rule,
	RuleCollector,
} from "@o3co/auth.policy-verifier.core";
import { createConsoleLogger } from "@o3co/auth.policy-verifier.core";
import {
	type CedarDecision,
	type CedarEngine,
	type LoadedCedarPolicySet,
	resolveCedarEngine,
} from "./engine.mjs";
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
	/**
	 * Which registered `CedarEngine` evaluates the set — `"wasm"` is the
	 * in-process evaluator `@o3co/auth.policy-verifier.cedar-wasm` registers
	 * when imported. Absent: the first registered of `wasm`, `http`, so a
	 * deployment that imports the wasm package gets it without saying so.
	 * Naming an engine that is not registered refuses to start, naming the
	 * package that would register it. See `resolveCedarEngine`.
	 */
	engine?: string;
	/** Rule group the Cedar decision joins AND-evaluation as. Default `"cedar"`. */
	ruleType?: string;
	/**
	 * What the rule answers when Cedar reports no determining policy — no
	 * `permit` matched and no `forbid` matched.
	 *
	 * | value | the group | choose it when |
	 * | --- | --- | --- |
	 * | `"deny"` (**default**) | fails | Cedar is authoritative over the surface it is asked about — including the common case where it is the only rule group |
	 * | `"abstain"` | passes | Cedar is one group beside TypeScript rules that own the rest of the surface, and abstaining is the intent |
	 *
	 * `"deny"` is Cedar's own implicit deny, and it is the default because the
	 * default is what a first deployment gets: with Cedar as the only rule
	 * group, `"abstain"` meant a request no policy matched passed the group and
	 * therefore passed. That is the one composition where an abstention is
	 * indistinguishable from an allow, and it is also the simplest one to
	 * assemble. The surrounding engine composes rule groups with default-deny;
	 * this now matches it.
	 *
	 * `"abstain"` stays selectable and is the right answer during a migration:
	 * the policy set covers part of the surface, the TypeScript rules still hold
	 * the rest, and the Cedar group is meant to have no opinion outside its own
	 * coverage. Choosing it is a statement that another group will decide.
	 *
	 * Neither value affects an evaluation error, which always denies — see the
	 * class doc comment's answer table.
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

/**
 * Evaluates a Cedar policy set as one core rule, through whichever
 * `CedarEngine` the deployment registered.
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
 * ## Why evaluation happens in the rule, not in `collect`
 *
 * The attribute and rule *collectors* run concurrently, so `collect` never
 * sees the merged attributes — and the point of the design is that Cedar
 * policies decide over what the attribute collectors gathered. The rule runs
 * after both pipelines, with that map. Cedar evaluation is a deterministic
 * function of `(loaded policy set, request)` with the request built from
 * `attrs` alone, so the rule satisfies the purity contract exactly: the policy
 * set and mapping are fixed at boot, nothing of `CollectorContext` is
 * retained, and equal attributes give equal answers. The rule object is built
 * once, in `create` — the hoisted form `metrics.test.mts` documents as the
 * strongest compliance shape.
 *
 * ## Which kind of rule
 *
 * The engine decides. A synchronous policy set (in-process wasm) becomes a
 * `Rule` and is asked through `verify`; an asynchronous one (an out-of-process
 * evaluator, #225) becomes an `AsyncRule` and is asked through `decide`, under
 * the server's rule deadline. Everything else — config, mapping, the answer
 * table below, the `ruleType` / `code` / `message` the decision reports — is
 * the same, so switching engines is a dependency change, not a config change.
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
 * | `deny` | no determining policy | `onNoDeterminingPolicy` (default `"deny"`) |
 * | anything | evaluation errors | **fail, and log** |
 * | — | the call itself failed | **fail, and log** |
 *
 * The errors row is unconditional — an evaluation error is never an
 * abstention. Cedar treats a policy that errors as not satisfied, so a
 * `forbid` that errors stops forbidding and the top-level decision can read
 * `allow`; the errors check runs first precisely so that a broken input fails
 * closed. The last row is the engine not answering at all (`CedarEngineError`,
 * a rejected call): also a deny, also logged, never an abstention.
 */
export class CedarPolicyRuleCollector implements RuleCollector {
	private constructor(private readonly rule: AnyRule) {}

	/**
	 * Validates the config entry, loads the policy set through the selected
	 * engine and fixes the rule. Asynchronous because an engine's `load` may
	 * be — an out-of-process engine takes the policy set over the network —
	 * and a set that cannot be loaded must refuse to start here, at boot,
	 * rather than deny every request (two-boundary validation). The module's
	 * registry factory is this function; `createApp` awaits it.
	 */
	static async create(
		config: CedarPolicyRuleCollectorConfig,
		options?: CedarPolicyRuleCollectorOptions,
	): Promise<CedarPolicyRuleCollector> {
		const raw = (config ?? {}) as Record<string, unknown>;

		const ruleType = raw.ruleType === undefined ? "cedar" : raw.ruleType;
		if (typeof ruleType !== "string" || ruleType.length === 0) {
			throw new Error(
				`CedarPolicyRuleCollector: ruleType must be a non-empty string, got ${JSON.stringify(raw.ruleType)}`,
			);
		}

		// Fail-closed by default: see the config field's doc comment. A pipeline
		// whose only rule group is Cedar would otherwise pass every request no
		// policy matched, which is the shape a first deployment assembles.
		const onNoDeterminingPolicy = (raw.onNoDeterminingPolicy ?? "deny") as NoDeterminingPolicy;
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

		const engine = selectEngine(raw.engine);
		const mapping: ResolvedMapping = resolveMapping(raw);
		const source = loadPolicySource(raw);

		// Boot-time compile, by the engine: a set it cannot parse refuses to
		// start here, with the engine's message naming the offending file.
		let policySet: LoadedCedarPolicySet;
		try {
			policySet = await engine.load(source);
		} catch (cause) {
			throw new Error(`CedarPolicyRuleCollector: ${errorMessage(cause)}`);
		}

		const logger = logEvaluationErrors
			? (options?.logger ?? createConsoleLogger({ collector: "CedarPolicyRuleCollector" }))
			: undefined;

		return new CedarPolicyRuleCollector(
			buildRule({
				ruleType,
				onNoDeterminingPolicy,
				engine,
				policySet,
				policySource: source.description,
				mapping,
				logger,
			}),
		);
	}

	async collect(_context: CollectorContext): Promise<AnyRule[]> {
		// Nothing is read from the context: everything the rule needs was fixed
		// at boot, and everything request-shaped reaches it through `attrs`.
		return [this.rule];
	}
}

function selectEngine(name: unknown): CedarEngine {
	try {
		return resolveCedarEngine(name);
	} catch (cause) {
		throw new Error(`CedarPolicyRuleCollector: ${errorMessage(cause)}`);
	}
}

interface BoundRule {
	ruleType: string;
	onNoDeterminingPolicy: NoDeterminingPolicy;
	engine: CedarEngine;
	policySet: LoadedCedarPolicySet;
	policySource: string;
	mapping: ResolvedMapping;
	logger: Logger | undefined;
}

function buildRule(bound: BoundRule): AnyRule {
	const { ruleType, onNoDeterminingPolicy, engine, policySet, policySource, mapping, logger } =
		bound;
	// `ruleType` too: two collectors over the same source (two inline sets, one
	// directory twice) are told apart in a log line only by the group they decide for.
	const identity = { engine: engine.name, policySet: policySource, ruleType };
	const base = { ruleType, code: "cedar_deny", message: "Denied by Cedar policy" };

	// Shared by both kinds of rule: request building and answer interpretation
	// are the same function of `attrs`; only the call in between differs.
	const request = (attrs: ReadonlyAttributes): CedarRequest | undefined => {
		try {
			return buildCedarRequest(mapping, attrs);
		} catch (cause) {
			logger?.error(
				{ ...identity, reason: errorMessage(cause) },
				"cedar request could not be built from attributes — denying",
			);
			return undefined;
		}
	};
	const callFailed = (cause: unknown): false => {
		logger?.error(
			{ ...identity, reason: errorMessage(cause) },
			"cedar authorization call failed — denying",
		);
		return false;
	};
	const interpret = (answer: CedarDecision): boolean => {
		if (answer.errors.length > 0) {
			// Checked before the decision on purpose: an erroring `forbid` stops
			// forbidding, so `decision` can read "allow" exactly when it is least
			// trustworthy. Never an abstention.
			logger?.error(
				{ ...identity, decision: answer.decision, errors: [...answer.errors] },
				"cedar policy evaluation raised errors — denying",
			);
			return false;
		}
		if (answer.decision === "allow") return true;
		if (answer.reason.length === 0) return onNoDeterminingPolicy === "abstain";
		return false;
	};

	if (!policySet.async) {
		const rule: Rule = {
			...base,
			verify(attrs) {
				const built = request(attrs);
				if (built === undefined) return false;
				let answer: CedarDecision;
				try {
					answer = policySet.isAuthorized(built);
				} catch (cause) {
					return callFailed(cause);
				}
				return interpret(answer);
			},
		};
		return rule;
	}

	const rule: AsyncRule = {
		...base,
		async decide(attrs, signal) {
			const built = request(attrs);
			if (built === undefined) return false;
			let answer: CedarDecision;
			try {
				answer = await policySet.isAuthorized(built, signal);
			} catch (cause) {
				return callFailed(cause);
			}
			return interpret(answer);
		},
	};
	return rule;
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
