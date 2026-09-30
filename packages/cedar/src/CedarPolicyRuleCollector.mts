// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The rule collector that puts a Cedar policy set into core's evaluation as a
 * single rule. `create` resolves the engine and loads the policy set once, at
 * boot; `collect` hands back that one rule, which builds the Cedar request from
 * the merged attributes on each call and reports how the evaluation behind its
 * answer went.
 */

import type {
	AnyRule,
	AsyncRule,
	CollectorContext,
	EvaluatedRevision,
	Logger,
	ReadonlyAttributes,
	ReportRuleEvaluation,
	Rule,
	RuleCollector,
	RuleEvaluation,
} from "@o3co/auth.policy-verifier.core";
import { createConsoleLogger } from "@o3co/auth.policy-verifier.core";
import {
	type CedarDecision,
	type CedarEngine,
	CedarEngineError,
	type ForeignAnswer,
	type LoadedCedarPolicySet,
	registeredCedarEngines,
	resolveCedarEngine,
} from "./engine.mjs";
import {
	buildCedarRequest,
	type CedarRequest,
	type ResolvedMapping,
	resolveMapping,
	type SharedEntity,
} from "./mapping.mjs";
import { loadPolicySource } from "./policySource.mjs";

/** What the rule answers when no policy determined the request (see below). */
export type NoDeterminingPolicy = "abstain" | "deny";

const NO_DETERMINING_POLICIES: readonly NoDeterminingPolicy[] = ["abstain", "deny"];

/** Config entry accepted by `CedarPolicyRuleCollector`. */
export interface CedarPolicyRuleCollectorConfig {
	/** Directory of `*.cedar` files, read in name order. XOR `policies`. */
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
	/**
	 * HTTP engine only: the agent's base URL. Absent, `CEDAR_ENDPOINT`; neither
	 * refuses to start, naming this key and the wasm package. Plain `http://` is
	 * accepted for loopback hosts only. See `cedarHttpEngine`.
	 */
	endpoint?: string;
	/** HTTP engine only: the agent's `Authorization` value. Absent, `CEDAR_AUTHENTICATION`. */
	authentication?: string;
	/**
	 * HTTP engine only: the most bytes read from one answer from the agent. A
	 * longer answer is refused — a deny. Absent, 1 MiB
	 * (`CEDAR_ANSWER_MAX_BYTES`). A whole number of bytes from 1 KiB to
	 * 256 MiB, as a number or a numeric string (what a HOCON env substitution
	 * delivers); anything else refuses to start. It bounds the agent's copy of
	 * the whole policy set too — its answer to the push at boot, and each
	 * read-back — so a set the agent re-prints past it fails boot.
	 */
	maxAnswerBytes?: number | string;
	/**
	 * HTTP engine only: the most one read-back of the agent's policy set
	 * waits for the next, while answers are not refused — each wait is drawn
	 * from half of it to all of it. Absent, 30 s
	 * (`CEDAR_READ_BACK_INTERVAL_MS`). A whole number of milliseconds from 1000
	 * to 3600000, as a number or a numeric string; anything else refuses to
	 * start.
	 */
	readBackIntervalMs?: number | string;
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
	 * `"deny"` is Cedar's own implicit deny and matches the engine's
	 * default-deny across groups. With Cedar as the only rule group,
	 * `"abstain"` would pass every request no policy matched. Neither value
	 * affects an evaluation error, which always denies.
	 *
	 * `"abstain"` is refused at boot over an asynchronous (out-of-process)
	 * engine: a remote engine that lost the policy set — a restarted agent comes
	 * back empty — answers every request "no determining policy", which the port
	 * cannot tell from a covered request that matched nothing, so every `forbid`
	 * would silently stop applying.
	 */
	onNoDeterminingPolicy?: NoDeterminingPolicy;
	/**
	 * Whether the rule logs Cedar evaluation errors (default `true`), and with
	 * them a request it could not build and a failed call. Faults of the
	 * deployment are logged whatever this says (see the class doc comment).
	 *
	 * The error branch is load-bearing: Cedar answers a policy that reads a
	 * missing attribute with `decision: "deny"` and the cause only in
	 * `diagnostics.errors` — without this log, a typo'd attribute mapping is
	 * indistinguishable from a policy deny. The healthy path never logs.
	 */
	logEvaluationErrors?: boolean;
	/**
	 * Whether every decision must be able to say which policy revision was
	 * evaluated. Default `false`.
	 *
	 * Each answer's `evaluation` names the revision only when the engine vouches
	 * for it (`CedarDecision.revision`); otherwise it reads `revision: null`,
	 * with what this collector loaded beside it as `loadedRevision`. Set this
	 * when the audit has to name the policies behind every decision: an answer
	 * nobody vouched for is then a logged deny instead of a permit of unknown
	 * origin.
	 *
	 * Refused at boot over an engine that does not declare `confirmsRevision` —
	 * the http engine, since cedar-agent does not report what it evaluated —
	 * because there every answer would be that deny.
	 */
	requireConfirmedRevision?: boolean;
	/**
	 * How the principal and the resource are described when they are one
	 * entity — a user acting on their own record. `"strict"` (default):
	 * the principal's mapping describes it and the resource's may repeat but
	 * not add; else the request is refused. `"merge"`: the resource mapping is
	 * trusted as the principal's, and what only one declares is added — see
	 * `SharedEntity`.
	 */
	sharedEntity?: SharedEntity;
	/** Entity/context mapping — see `resolveMapping` for the shape. */
	principal?: unknown;
	action?: unknown;
	resource?: unknown;
	context?: unknown;
}

/** Constructor options beyond the config entry (programmatic composition only). */
export interface CedarPolicyRuleCollectorOptions {
	/**
	 * Receives the collector's log lines, and is handed to the engine's `load`.
	 * Defaults to the console-backed logger.
	 */
	logger?: Logger;
}

/**
 * Evaluates a Cedar policy set as one core rule, through whichever
 * `CedarEngine` the deployment registered. The package README (Semantics;
 * Policy revision) describes the same behaviour for an operator.
 *
 * ## Why one rule, not a translation
 *
 * Core's evaluator is OR within a group and AND across groups, with no global
 * override; Cedar's forbid-overrides-permit is inexpressible in that algebra.
 * So the policy set is never translated into core rules — the real Cedar
 * evaluator runs, and its whole verdict enters AND-evaluation as a single
 * group: Cedar semantics inside the group, core semantics across groups,
 * composing only toward strictness.
 *
 * ## Why evaluation happens in the rule, not in `collect`
 *
 * The attribute and rule collectors run concurrently, so `collect` never sees
 * the merged attributes the policies decide over; the rule runs after both
 * pipelines, with that map. The request is built from `attrs` alone, and the
 * policy set and mapping are fixed at boot with nothing of `CollectorContext`
 * retained, so the answer depends on nothing of the request but `attrs`:
 * in-process, equal attributes give equal answers; over http, the agent's set
 * and the read-back's state can change one. The rule object is built once, in
 * `create`.
 *
 * The rule also logs, and no log line changes an answer. A request that could
 * not be built, a failed call and an evaluation error are logged unless
 * `logEvaluationErrors = false`. Faults of the deployment are always logged:
 * an answer from a revision or policies this collector did not load, an
 * `allow` naming no policy, an unvouched answer under
 * `requireConfirmedRevision` — and, once, that knob set on a rule asked
 * without a reporter.
 *
 * ## Which kind of rule
 *
 * The engine decides. A synchronous policy set (in-process wasm) becomes a
 * `Rule` and is asked through `verify`; an asynchronous one (an out-of-process
 * evaluator) becomes an `AsyncRule` and is asked through `decide`, under the
 * server's rule deadline. Everything else — config, mapping, the answer table
 * below, the `ruleType` / `code` / `message` the decision reports — is the
 * same, so switching engines is a dependency change, not a config change.
 *
 * ## Answer interpretation
 *
 * | Cedar answered | with | the rule answers | `evaluation.status` |
 * | --- | --- | --- | --- |
 * | `allow` | no errors | pass | `completed` |
 * | `deny` | determining `forbid` | fail | `completed` |
 * | `deny` | no determining policy | `onNoDeterminingPolicy` (default `"deny"`) | `completed` |
 * | anything | evaluation errors | **fail, and log** | `failed` |
 * | — | the call itself failed, or answered something that is not a decision (an `allow` naming no policy included) | **fail, and log** | `failed` |
 * | — | the request could not be built, so Cedar was not asked | **fail, and log** | `not_invoked` |
 * | anything | a revision other than the one loaded, or policies it never loaded | **fail, and log** | `failed` |
 *
 * The errors row is unconditional — an evaluation error is never an
 * abstention. Cedar treats a policy that errors as not satisfied, so a
 * `forbid` that errors stops forbidding and the top-level decision can read
 * `allow`; the errors check runs first so that a broken input fails closed.
 * The call-failed row is the engine not answering at all (`CedarEngineError`,
 * a rejected call): also a deny, also logged, never an abstention.
 *
 * ## What the rule reports about each answer
 *
 * Every failing row is the same `cedar_deny` to the evaluator, and must be.
 * But only the first three are a policy's answer, and an audit record that
 * attributed the rest to the policy set would name policies that did not
 * decide, or never ran. So the rule **reports** the last column, and beside it
 * the revision of the policy set: as `revision` when the engine vouched for
 * this answer, as `revision: null` with `loadedRevision` when it did not, and
 * not at all for `not_invoked`. It goes to the reporter core hands `verify` /
 * `decide` for that one call (`ReportRuleEvaluation`) — built from this call's
 * own values, with nothing kept on the rule, which answers concurrent
 * decisions.
 *
 * A completed answer also names the policies Cedar says determined it,
 * sorted, through the reporter's own `boundDeterminingPolicies` — the bounds
 * of the core that checks the report. A reporter without it, from a core that
 * predates the keys, is told the evaluation without them.
 *
 * The rule still **answers a boolean**: an evaluator that passes no reporter —
 * a copy of core one release older, in a mixed install — reads the boolean
 * and records no evaluation. Returned in the answer, the evaluation would be
 * an object that evaluator reads by truthiness, every deny as an allow.
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

		const rawRequire = raw.requireConfirmedRevision;
		if (rawRequire !== undefined && typeof rawRequire !== "boolean") {
			throw new Error(
				`CedarPolicyRuleCollector: requireConfirmedRevision must be a boolean, got ${JSON.stringify(rawRequire)}`,
			);
		}
		const requireConfirmedRevision = rawRequire ?? false;

		const engine = selectEngine(raw.engine);
		const mapping: ResolvedMapping = resolveMapping(raw);
		const source = loadPolicySource(raw);
		// Read here, once, before an engine is handed `source`. What this
		// collector reports as loaded is its own reading of what it loaded — not
		// a property an engine could have rewritten by the time `load` returns.
		const loadedRevision = source.revision;
		const logger =
			options?.logger ?? createConsoleLogger({ collector: "CedarPolicyRuleCollector" });

		// Said once, at boot. Named in config, the engine is information. Left
		// to the default, which evaluator decides is settled by what happens to
		// be imported — a transitive dependency pulling in cedar-wasm flips a
		// deployment from out-of-process to in-process — and an operator reading
		// the config cannot see it, so it is a warning.
		const selection = {
			engine: engine.name,
			policySet: source.description,
			files: source.files.length,
		};
		if (raw.engine === undefined) {
			logger.warn(
				{ ...selection, registered: registeredCedarEngines() },
				"cedar engine selected by default — set engine in the collector's config so the config says which evaluator decides",
			);
		} else {
			logger.info(selection, "cedar engine selected by config");
		}

		if (engine.async && onNoDeterminingPolicy === "abstain") {
			// See the config field's doc comment: over a remote engine, "no
			// determining policy" is also what an engine that lost the set says.
			// Refused before `load`, which pushes the set and reserves the agent.
			throw new Error(
				`CedarPolicyRuleCollector: onNoDeterminingPolicy = "abstain" cannot be used with the asynchronous "${engine.name}" engine — an engine that lost the policy set (a restarted agent comes back empty) answers "no determining policy" to every request, which abstain would pass. Use "deny", or evaluate in-process: import "@o3co/auth.policy-verifier.cedar-wasm" and set engine = "wasm"`,
			);
		}

		if (requireConfirmedRevision && engine.confirmsRevision !== true) {
			// See the config field's doc comment. Refused before `load` for the
			// reason above: serving, every answer of this engine would be a deny.
			throw new Error(
				`CedarPolicyRuleCollector: requireConfirmedRevision = true cannot be used with the "${engine.name}" engine — it does not report which policy revision an answer was evaluated against, so no decision could name one. Evaluate in-process: import "@o3co/auth.policy-verifier.cedar-wasm" and set engine = "wasm"; or leave requireConfirmedRevision off, and the revision this collector loaded is recorded as loadedRevision`,
			);
		}

		// Boot-time compile, by the engine: a set it cannot parse refuses to
		// start here, with the engine's message naming the offending file.
		let policySet: LoadedCedarPolicySet;
		try {
			policySet = await engine.load(source, { config: raw, logger });
		} catch (cause) {
			throw new Error(`CedarPolicyRuleCollector: ${errorMessage(cause)}`);
		}

		if (policySet.async !== engine.async) {
			// The declaration the check above trusted was wrong: an engine bug,
			// refused rather than run with a guard that did not apply.
			throw new Error(
				`CedarPolicyRuleCollector: the "${engine.name}" engine declares async = ${engine.async} but loaded a policy set with async = ${policySet.async}`,
			);
		}

		return new CedarPolicyRuleCollector(
			buildRule({
				ruleType,
				onNoDeterminingPolicy,
				engine,
				policySet,
				policySource: source.description,
				loadedRevision,
				requireConfirmedRevision,
				mapping,
				logger: logEvaluationErrors ? logger : undefined,
				faultLogger: logger,
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
	/** `PolicySource.revision`, read before the set was handed to `engine.load`. */
	loadedRevision: string;
	requireConfirmedRevision: boolean;
	mapping: ResolvedMapping;
	/**
	 * For evaluation errors, requests that could not be built and failed
	 * calls; absent under `logEvaluationErrors = false`.
	 */
	logger: Logger | undefined;
	/**
	 * For what `logEvaluationErrors` does not govern: an engine answering from
	 * a policy set this collector did not load, an `allow` naming no policy, an
	 * answer not vouched for under `requireConfirmedRevision`, and the one-time
	 * warning that that knob's revisions go unrecorded. Those are faults of the
	 * deployment, not of a policy reading a missing attribute, and are never
	 * silent.
	 */
	faultLogger: Logger;
}

/**
 * The labels an engine may give a foreign answer (`ForeignAnswer.why`) — the
 * only text of it logged. A record, so a label added to the type and not here
 * fails to compile rather than going unlogged.
 */
const FOREIGN_LABELS: Readonly<Record<ForeignAnswer["why"], true>> = {
	"unknown policy": true,
	"unreadable policy": true,
	"altered policy set": true,
	"unverifiable policy set": true,
};

/**
 * The labels of an engine's read-back: its agent was found holding
 * another set, or not showing one — whether or not it had been asked, no
 * answer of it is used. Logged on a line of their own, so an agent gone down
 * does not read as an answer from someone else's set.
 */
const READ_BACK_REFUSALS: ReadonlySet<string> = new Set<ForeignAnswer["why"]>([
	"altered policy set",
	"unverifiable policy set",
]);

/**
 * What of a `foreign` mark the log carries: the engine's fixed label and a
 * 16-hex mark, each only in that shape — never text the evaluator chose.
 */
function foreignDetail(foreign: unknown): { foreign?: string; mark?: string } {
	const { why, mark } = (typeof foreign === "object" && foreign !== null ? foreign : {}) as {
		why?: unknown;
		mark?: unknown;
	};
	return {
		...(typeof why === "string" && Object.hasOwn(FOREIGN_LABELS, why) ? { foreign: why } : {}),
		...(typeof mark === "string" && /^[0-9a-f]{16}$/.test(mark) ? { mark } : {}),
	};
}

/** How a reporter bounds determining policies — the checking core's own. */
type DeterminingPolicyBounder = NonNullable<ReportRuleEvaluation["boundDeterminingPolicies"]>;

/** One answer of the rule, before it is split into the boolean and the report. */
interface Answered {
	readonly passed: boolean;
	/** What an evaluator is told. */
	readonly evaluation: RuleEvaluation;
	/**
	 * What a reporter that bounds determining policies is told instead: the
	 * same completed evaluation, naming the policies that
	 * determined it under that reporter's bounds. Present only when Cedar ran
	 * to an answer.
	 */
	readonly naming?: (bound: DeterminingPolicyBounder) => RuleEvaluation;
}

function buildRule(bound: BoundRule): AnyRule {
	const {
		ruleType,
		onNoDeterminingPolicy,
		engine,
		policySet,
		policySource,
		loadedRevision,
		requireConfirmedRevision,
		mapping,
		logger,
		faultLogger,
	} = bound;
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
	// The ways an answer accounts for the revision. Constants of the
	// rule — the loaded revision is fixed at boot — so equal attributes give
	// an equal report, which is what the purity contract asks of it.
	const NOT_INVOKED: Answered = Object.freeze({
		passed: false,
		evaluation: Object.freeze({ status: "not_invoked" }),
	});
	/** Nothing vouched for what ran: the call failed, or the engine does not say. */
	const unconfirmed = (status: "completed" | "failed"): RuleEvaluation => ({
		status,
		revision: null,
		loadedRevision,
	});
	/**
	 * Splits an answer the way core takes it: the evaluation to the reporter
	 * of this one call, the boolean back. `report` is absent when the evaluator
	 * asking predates it, and the boolean is then the whole answer — see the
	 * class doc comment for why that, and not a richer return value.
	 */
	const deliver = (answered: Answered, report: ReportRuleEvaluation | undefined): boolean => {
		if (report === undefined) {
			warnUnreported();
			return answered.passed;
		}
		// Determining policies are named only through the reporter's own
		// bounding. A core that predates them has none — it would refuse the keys
		// and fail the decision — and is told the evaluation without them.
		const bound = report.boundDeterminingPolicies;
		report(
			bound !== undefined && answered.naming !== undefined
				? answered.naming(bound)
				: answered.evaluation,
		);
		return answered.passed;
	};
	// `requireConfirmedRevision` is set so that every decision's record names
	// its policies. Asked without a reporter — an evaluator that predates it,
	// which in practice is a copy of core one release older beside this package
	// — the rule still enforces the knob and still answers correctly, and none
	// of it is recorded. Nothing else would say so; said once, not per request.
	// The answer never depends on whether a reporter was passed.
	let warnedUnreported = false;
	const warnUnreported = (): void => {
		if (!requireConfirmedRevision || warnedUnreported) return;
		warnedUnreported = true;
		faultLogger.warn(
			identity,
			"requireConfirmedRevision is set, but this rule was asked without a reporter, so the revisions it enforces are not being recorded — the evaluator running it predates evaluation reports; upgrade @o3co/auth.policy-verifier.core and .server together with this package",
		);
	};

	const callFailed = (cause: unknown): Answered => {
		logger?.error(
			{ ...identity, reason: errorMessage(cause) },
			"cedar authorization call failed — denying",
		);
		return { passed: false, evaluation: unconfirmed("failed") };
	};
	const interpret = (answer: CedarDecision): Answered => {
		// The port's type is the contract; an engine written outside the type
		// may not keep to it, and what it answered is then no decision at all —
		// the call failed, whatever else it said.
		if (typeof answer !== "object" || answer === null) {
			return callFailed(
				new CedarEngineError("cedar engine answered something that is not a decision"),
			);
		}
		if (answer.revision !== undefined && answer.revision !== loadedRevision) {
			// The engine holds a policy set this collector did not load — replaced
			// under it, or never its own. A permit from there is a permit from
			// somebody else's policies, so it is refused before the decision is
			// read. What the engine named is not repeated: it is the engine's text.
			// On `faultLogger`: not an evaluation error, so not `logEvaluationErrors`' to silence.
			faultLogger.error(
				{ ...identity, loadedRevision },
				"cedar engine answered from a policy revision other than the one loaded — denying",
			);
			return { passed: false, evaluation: unconfirmed("failed") };
		}
		if (answer.foreign !== undefined && answer.foreign !== null) {
			// The engine cannot vouch for what it evaluated, but it can tell this
			// was not it: the answer names policies it never loaded. The same
			// fault as a foreign revision, logged the same way — before the errors
			// are looked at, so it is never an evaluation error to silence.
			// A refusal from the engine's read-back is said as that: no
			// answer of the agent's is used, whether or not it was asked, and an
			// agent gone down is refused this way too — so it must not read as an
			// answer from someone else's set.
			const detail = foreignDetail(answer.foreign);
			faultLogger.error(
				{ ...identity, loadedRevision, ...detail },
				detail.foreign !== undefined && READ_BACK_REFUSALS.has(detail.foreign)
					? "cedar engine's agent does not hold, or does not show, the policy set this verifier loaded — denying without using its answer"
					: "cedar engine answered from a policy set this verifier did not load — denying",
			);
			return { passed: false, evaluation: unconfirmed("failed") };
		}
		if (!Array.isArray(answer.reason) || !Array.isArray(answer.errors)) {
			// After the revision check, so an answer from a foreign set is logged
			// as that. A string here would be read by character — its letters
			// recorded as policy ids, or its length taken for errors.
			return callFailed(
				new CedarEngineError(
					"cedar engine answered a decision whose reason or errors is not a list",
				),
			);
		}
		if (answer.decision === "allow" && answer.reason.length === 0) {
			// Cedar allows only on a permit that applied, so an allow naming none
			// is no answer of Cedar's — and it is what an engine wrapper that
			// dropped `foreign` would hand on from a set this verifier did not load.
			// A fault of the deployment, like `foreign` itself: never silent.
			faultLogger.error(
				{ ...identity, loadedRevision },
				"cedar engine answered allow naming no determining policy — no answer of Cedar's; denying",
			);
			return { passed: false, evaluation: unconfirmed("failed") };
		}
		const confirmed = answer.revision !== undefined;
		if (requireConfirmedRevision && !confirmed) {
			// The engine declared `confirmsRevision` — boot checked — and this
			// answer did not name one. Denied rather than let through unnamed.
			faultLogger.error(
				{ ...identity, loadedRevision },
				"cedar engine did not name the policy revision it evaluated, and requireConfirmedRevision is set — denying",
			);
			return { passed: false, evaluation: unconfirmed("failed") };
		}
		const evaluatedRevision: EvaluatedRevision = confirmed
			? { revision: loadedRevision }
			: { revision: null, loadedRevision };

		if (answer.errors.length > 0) {
			// Checked before the decision on purpose: an erroring `forbid` stops
			// forbidding, so `decision` can read "allow" exactly when it is least
			// trustworthy. Never an abstention.
			logger?.error(
				{ ...identity, decision: answer.decision, errors: [...answer.errors] },
				"cedar policy evaluation raised errors — denying",
			);
			return { passed: false, evaluation: { status: "failed", ...evaluatedRevision } };
		}
		// From here Cedar ran to an answer, and the answer is the policies' own —
		// "no policy determined the request" included, under either setting.
		const evaluation: RuleEvaluation = { status: "completed", ...evaluatedRevision };
		// Named for their files by the engine (`namePolicies`). Cedar keeps
		// `reason` in a set, whose order is not the attributes', so it is sorted:
		// equal attributes, equal report. Only when a reporter asks — an older
		// core's never does — and each id once before the sort.
		const naming = (bound: DeterminingPolicyBounder): RuleEvaluation => ({
			status: "completed",
			...evaluatedRevision,
			...bound([...new Set(answer.reason)].sort()),
		});
		const answered = (passed: boolean): Answered => ({ passed, evaluation, naming });
		if (answer.decision === "allow") return answered(true);
		if (answer.reason.length === 0) return answered(onNoDeterminingPolicy === "abstain");
		return answered(false);
	};

	if (!policySet.async) {
		const rule: Rule = {
			...base,
			verify(attrs, report) {
				const built = request(attrs);
				if (built === undefined) return deliver(NOT_INVOKED, report);
				let answer: CedarDecision;
				try {
					answer = policySet.isAuthorized(built);
				} catch (cause) {
					return deliver(callFailed(cause), report);
				}
				return deliver(interpret(answer), report);
			},
		};
		return rule;
	}

	const rule: AsyncRule = {
		...base,
		async: true,
		async decide(attrs, signal, report) {
			const built = request(attrs);
			if (built === undefined) return deliver(NOT_INVOKED, report);
			let answer: CedarDecision;
			try {
				answer = await policySet.isAuthorized(built, signal);
			} catch (cause) {
				// An aborted call is not an engine outage: the signal carries the
				// evaluator's timeout or the caller's departure, and it has to reach
				// the evaluator as such — folded into a deny, a timeout read as
				// `cedar_deny` and a departed caller as a failing engine.
				if (signal.aborted) throw signal.reason;
				return deliver(callFailed(cause), report);
			}
			return deliver(interpret(answer), report);
		},
	};
	return rule;
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
