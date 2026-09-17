// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { UntrustedRequestContext } from "./untrusted.mjs";

/** Structured form of a resource string after parsing. */
export interface Resource {
	raw: string;
	resourceType: string;
	resourceId?: string;
}

/**
 * Parses a raw resource string (e.g. `"orders/42"`) into a `Resource`.
 * Implementations define their own syntax; the resource string is pipeline
 * input and must round-trip via `raw`.
 */
export interface ResourceParser {
	parse(raw: string): Resource;
}

/**
 * Request-scoped input shared across every attribute and rule collector for a single verify call.
 *
 * Every field but one is input the deployment vouches for: `subject` was
 * populated by the transport from a credential it verified, `resource` and
 * `action` were validated by it, `headers` were set by it. `requestContext` is
 * the caller's own — see {@link UntrustedRequestContext} for why it is sealed
 * rather than plain.
 */
export interface CollectorContext {
	subject: SubjectAttributes;
	resource: Resource;
	action: string;
	headers?: Record<string, string>;
	/** Caller-supplied; read it with `readUntrustedRequestContext`. */
	requestContext?: UntrustedRequestContext;
	/**
	 * The raw, replayable credential the request arrived under — present ONLY
	 * when the composition opted in (`verify.credentialToCollectors =
	 * "expose"`, #175). Absent by default: collectors get verified claims, not
	 * the credential, because a collector that logs its context would otherwise
	 * leak a live token. The one legitimate use is a project-side collector
	 * calling a downstream API *as the subject* (token forwarding/exchange);
	 * that deployment states the exposure in config, where it is greppable.
	 * NEVER log this field.
	 */
	credential?: string;
	/**
	 * Cancellation for this collect, and the one field that is not a fact about
	 * the request (#115).
	 *
	 * It aborts when this collector overruns its budget, when the pipeline
	 * overruns its end-to-end deadline, when a sibling collector has already
	 * failed the decision, or when the caller went away. Pass it to whatever
	 * this collector waits on — `fetch(url, { signal: context.signal })`, a
	 * driver's cancellation option — so the work stops rather than being merely
	 * stopped waiting for.
	 *
	 * Always present: the pipeline supplies one per collector per decision, so
	 * there is no `?.` and no "unbounded if nobody wired it" case. Honouring it
	 * is not what makes the deadline hold — the pipeline abandons a collector
	 * that ignores it — but a collector that ignores it leaves its outbound call
	 * running after the decision it belonged to is gone.
	 *
	 * It is a live handle on the request, so the rule contract applies to it
	 * exactly as to the rest of the context: a **collector** may hold it for the
	 * duration of `collect`; a **rule** must not carry it into `verify`. See
	 * AGENTS.md, "Collector / Rule / Attribute Contract".
	 */
	signal: AbortSignal;
}

/**
 * What a pipeline is handed: the request, without the per-collector `signal`
 * the pipeline itself supplies.
 *
 * The two shapes are deliberately different types. A transport builds facts
 * about a request and has no per-collector signal to give — that one belongs to
 * the fan-out, is different for every collector, and aborts on bounds the
 * transport knows nothing about. `signal` here is the optional *caller-side*
 * cancellation (a client that hung up, an outer deadline); the pipeline links
 * it into its own, so aborting it cancels every collector in flight.
 */
export type CollectorRequest = Omit<CollectorContext, "signal"> & {
	/** Optional caller-side cancellation, linked into the pipeline's own. */
	signal?: AbortSignal;
};

/**
 * Map of attribute keys to values produced by attribute collectors.
 * Values are `unknown` so collectors can contribute any shape; downstream rules
 * are responsible for narrowing.
 *
 * Mutable on purpose: a collector builds its slice by writing into one, and
 * `AttributePipeline` merges those slices the same way. It is the *rule's* view
 * of the merged result that is narrowed — see {@link ReadonlyAttributes}.
 */
export type Attributes = Map<string, unknown>;

/**
 * The read-only view of {@link Attributes} that a rule is judged against.
 *
 * The evaluator hands the same live map to every rule in every group, so a rule
 * that wrote into it would silently change the inputs of every group evaluated
 * after it. Rules only ever read, so they are handed something that can only be
 * read — see AGENTS.md "Collector / Rule / Attribute Contract".
 */
export type ReadonlyAttributes = ReadonlyMap<string, unknown>;

/**
 * Produces attributes for a request. One collector contributes one logical slice
 * (e.g. subject id, scopes, roles). Results are merged by the `AttributePipeline`.
 */
export interface AttributeCollector {
	collect(context: CollectorContext): Promise<Attributes>;
}

/**
 * A single authorization rule. `verify` runs against the merged attributes and
 * returns whether the rule passes; `ruleType` groups alternative rules (OR within
 * a group), and `code` / `message` surface on deny.
 *
 * `verify` must be a deterministic, side-effect-free function of `attrs`: equal
 * attributes give equal answers, and nothing the engine cannot see may decide
 * the outcome. A rule may hold values fixed at collect time — *what it looks
 * for* — but must not retain the `CollectorContext` and read it here. See
 * AGENTS.md "Collector / Rule / Attribute Contract".
 */
export interface Rule {
	ruleType: string;
	code: string;
	message: string;
	/** A boolean, or a `RuleVerdict` when the rule has an evaluation to report. */
	verify(attrs: ReadonlyAttributes): RuleAnswer;
}

/**
 * How one invocation of the policy evaluator behind a rule went (#244).
 *
 * A rule that fronts an evaluator — a Cedar policy set, an OPA bundle — denies
 * for reasons that are not a policy's: the request could not be built, the
 * engine did not answer, the evaluation raised errors. All of them are a
 * failing rule, and have to be, because the rule fails closed; but an audit
 * record that attributed each of them to the policy would name a policy that
 * never ran. XACML keeps the same two things apart as `Decision` and `Status`.
 *
 * | status | the evaluator | the answer is |
 * | --- | --- | --- |
 * | `completed` | ran to an answer without errors | the policy's own — a permit, a forbid, or no policy determining the request |
 * | `failed` | was invoked and did not produce a clean answer | the rule failing closed |
 * | `not_invoked` | was never asked | the rule failing closed before it got that far |
 */
export type RuleEvaluationStatus = "completed" | "failed" | "not_invoked";

/**
 * What a rule reports about the evaluation behind one answer: its
 * {@link RuleEvaluationStatus}, and which policy snapshot it concerned.
 *
 * `revision` is a claim about what was **evaluated**, so it is a string only
 * when the evaluator vouches for it. `null` is the explicit unknown — the
 * evaluator ran, and what it evaluated cannot be established, which is every
 * answer of a remote engine that does not say. What the deployment *loaded*
 * is then carried apart, as `loadedRevision`: worth recording, and not proof
 * of what ran. The two never share a name, so a consumer reading `revision`
 * cannot take a snapshot nobody confirmed for one that was evaluated.
 *
 * `not_invoked` has no revision key of either kind, by type and by the check
 * in `evaluate()`: an evaluator that was never asked evaluated nothing.
 *
 * A reference is `scheme:encoded` — {@link POLICY_REVISION_PATTERN}, the OCI
 * digest grammar — so `sha256:<64 hex>` for a content digest, and an engine
 * whose versions are not digests names its own scheme. What the reference
 * covers is its producer's to document: for `packages/cedar`, the policy files
 * and nothing else. It is never a promise of replay — attributes, mapping and
 * evaluator version decide an answer too.
 */
export type RuleEvaluation =
	| { readonly status: "not_invoked" }
	| { readonly status: "completed" | "failed"; readonly revision: string }
	| {
			readonly status: "completed" | "failed";
			readonly revision: null;
			readonly loadedRevision?: string;
	  };

/**
 * The shape a policy revision reference is held to: `scheme:encoded`, the OCI
 * image-spec digest grammar. Enforced by `evaluate()` on everything a rule
 * reports, because what a rule returns reaches the wire and the audit log — a
 * path, a label with spaces or policy text does not fit it.
 */
export const POLICY_REVISION_PATTERN = /^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]+$/;

/** Longest reference carried. `sha512:` and its 128 hex characters is 135. */
export const POLICY_REVISION_MAX_LENGTH = 256;

/**
 * A rule's answer with an account of the evaluation behind it (#244).
 *
 * It is the return value, and not a field on the rule or a callback, because
 * it is a fact about one invocation: the same rule object answers concurrent
 * decisions, and anything it kept between them would be one decision's
 * evaluation on another's record. Being part of the answer, it falls under the
 * purity contract with the rest of it — equal attributes, equal verdict.
 *
 * `evaluate()` copies `evaluation` onto this invocation's {@link RuleOutcome}
 * after checking it, and refuses a verdict it cannot read with a `TypeError`
 * attributed to the rule.
 */
export interface RuleVerdict {
	readonly passed: boolean;
	readonly evaluation?: RuleEvaluation;
}

/**
 * What `verify` / `decide` may answer. A rule with nothing to report keeps
 * answering a boolean.
 *
 * Read it with {@link ruleAnswerPassed}, never by truthiness: a failing
 * verdict is an object, and an object is truthy.
 */
export type RuleAnswer = boolean | RuleVerdict;

/**
 * Whether an answer is a pass — for code that asks a rule directly (a test, a
 * conformance suite) instead of through `evaluate()`. Strict on purpose: only
 * `true` and a verdict whose `passed` is `true` are a pass.
 */
export function ruleAnswerPassed(answer: RuleAnswer): boolean {
	return typeof answer === "object" && answer !== null ? answer.passed === true : answer === true;
}

/**
 * A rule whose answer comes from I/O — an out-of-process policy engine such as
 * Cedar over HTTP (#225). It cannot be a {@link Rule}: `verify` is synchronous
 * and, by contract, does no I/O. This is the additive form: the same
 * `ruleType` grouping, the same `code` / `message` on deny, the same reporting
 * in the decision's `reason`, and the same rule that the answer be a function
 * of `attrs` alone — a `CollectorContext` retained from collect time may no more
 * be read here than in `verify`, and the purity conformance suite checks
 * `decide` exactly as it checks `verify`.
 *
 * What differs is permitted cost: `decide` may do I/O, so it runs under a
 * deadline (`evaluate()`'s `ruleTimeoutMs`) and is handed a `signal` that aborts
 * when that budget — or the caller — ends. Pass the signal to `fetch`. A rule
 * that does not answer in time fails the decision as a deny of its own,
 * `RuleTimeoutError`, never as a pass.
 */
export interface AsyncRule {
	ruleType: string;
	code: string;
	message: string;
	/**
	 * The discriminant: what makes this an asynchronous rule. Explicit, as the
	 * policy-set union in cedar is, rather than read off the presence of
	 * `decide` — a synchronous rule that happens to carry an unrelated `decide`
	 * method must not be sent down the asynchronous path (v0.10.0 audit).
	 */
	readonly async: true;
	/** A boolean, or a `RuleVerdict` when the rule has an evaluation to report. */
	decide(attrs: ReadonlyAttributes, signal: AbortSignal): Promise<RuleAnswer>;
}

/** Either kind of rule. A collector may return both in one list. */
export type AnyRule = Rule | AsyncRule;

/** Tells the two kinds apart by the `async` discriminant. */
export function isAsyncRule(rule: AnyRule): rule is AsyncRule {
	return (rule as Partial<AsyncRule>).async === true;
}

/**
 * Produces rules for a request. A rule collector may return zero or more rules;
 * the `RulePipeline` flattens results from all collectors before evaluation.
 */
export interface RuleCollector {
	collect(context: CollectorContext): Promise<AnyRule[]>;
}

/** How one rule inside a group came out. */
export interface RuleOutcome {
	code: string;
	message: string;
	passed: boolean;
	/**
	 * What the rule reported about the evaluation behind this answer (#244) —
	 * checked and frozen by `evaluate()`. Absent when the rule reported none,
	 * which is every rule that has no policy source to identify: what decides
	 * for a TypeScript rule is the deployed code and its config.
	 */
	evaluation?: RuleEvaluation;
}

/**
 * How one rule group (`ruleType`) came out. Groups are the unit of
 * AND-evaluation, so this is the granularity at which "why" is answerable.
 *
 * `evaluated` always means the same thing: every rule that actually ran, in
 * evaluation order. The group is an OR, so a passing group stops at its first
 * passing rule — `evaluated` then ends with that rule, preceded by any
 * alternatives that were tried and failed before it; alternatives after it
 * never ran and are not reported. A failing group ran every alternative, so
 * `evaluated` lists them all.
 *
 * `satisfiedBy` marks the pass case explicitly: the rule that satisfied the
 * group, always the last element of `evaluated`. "What ran" is `evaluated`;
 * "what decided" is `satisfiedBy` on a pass, and on a fail the whole of
 * `evaluated` (every alternative refused).
 */
export type RuleGroupOutcome =
	| { ruleType: string; passed: true; evaluated: RuleOutcome[]; satisfiedBy: RuleOutcome }
	| { ruleType: string; passed: false; evaluated: RuleOutcome[] };

/**
 * Structured account of how a decision was reached, carried on both allow and
 * deny. A bare allow/deny cannot answer "why", and an engine placed behind the
 * same decision contract has to be able to report the same thing — OPA returns
 * a decision document and OpenFGA/Cedar name the tuple or policy that decided,
 * so the contract carries a reason rather than a single representative rule.
 */
export interface DecisionReason {
	/** Every rule group that was evaluated, in evaluation order. */
	groups: RuleGroupOutcome[];
}

/**
 * Outcome of `evaluate`. On `"deny"`, `code` and `message` come from the first
 * rule of the first failing group; `reason` accounts for every group.
 */
export type Decision =
	| { decision: "allow"; reason: DecisionReason }
	| { decision: "deny"; code: string; message: string; reason: DecisionReason };

/** Named bundle of permissions. Used by role-based attribute collectors. */
export interface Role {
	name: string;
	permissions: string[];
}

/**
 * Verified attributes of the subject a decision is being asked about — the
 * first element of the `(subject, resource, action, context)` quadruple every
 * engine behind the decision contract consumes.
 *
 * A bag, not a claim set: core names no field, reads no field, and does not
 * know what credential the transport verified. The transport that admitted the
 * request populates it — this repo's server spreads a signature-verified JWT's
 * claims into it, so under that server the keys are the token's claims (`sub`,
 * `azp`, `scope`, …) — and collectors narrow the values they promote, which is
 * where claim vocabulary belongs (see the builtins). Read-only because it is
 * shared across every collector of a decision: a collector writes attributes
 * into its own result, never into its input.
 */
export interface SubjectAttributes {
	readonly [key: string]: unknown;
}
