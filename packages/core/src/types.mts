// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The shared types every package builds on: the resource and its parser, the
 * request collectors read (`CollectorContext`), attributes, sync and async
 * rules and their collectors, the evaluation a rule reports (with the
 * policy-revision shape it is held to), and the decision `evaluate()` returns.
 */

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
	/**
	 * Answers a boolean. `report` is there for a rule that fronts a policy
	 * evaluator — see `ReportRuleEvaluation`; every other rule ignores it.
	 */
	verify(attrs: ReadonlyAttributes, report?: ReportRuleEvaluation): boolean;
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
 * {@link RuleEvaluationStatus}, which policy snapshot it concerned, and —
 * for a completed one — which policies determined the answer.
 *
 * `revision` is a claim about what was **evaluated**, so it is a string only
 * when the evaluator vouches for it. `null` is the explicit unknown — the
 * evaluator ran, and what it evaluated cannot be established, which is every
 * answer of a remote engine that does not say. What the deployment *loaded*
 * is then carried apart, as `loadedRevision`: worth recording, and not proof
 * of what ran. The two never share a name, so a consumer reading `revision`
 * cannot take a snapshot nobody confirmed for one that was evaluated.
 *
 * `not_invoked` has no revision key of either kind, and no determining
 * policies, by type and by the check in `evaluate()` — which refuses them
 * however the value is reached, inherited or through a getter included: an
 * evaluator that was never asked evaluated nothing.
 *
 * A reference is `scheme:encoded` — {@link POLICY_REVISION_PATTERN}, the OCI
 * digest grammar — so `sha256:<64 hex>` for a content digest, and an engine
 * whose versions are not digests names its own scheme. What the reference
 * covers is its producer's to document: for `packages/cedar`, the policy files
 * and nothing else. It is never a promise of replay — attributes, mapping and
 * evaluator version decide an answer too.
 *
 * `determiningPolicies` (#199) names the policies that determined a
 * **completed** answer — for an allow, the permits that applied; for a deny,
 * the forbids that did; an empty list when no policy applied to the request.
 * It is a set, in the order the rule reports it, and absent when the rule does
 * not know (a rule that fronts no evaluator reports nothing at all). A
 * `failed` evaluation carries none, checked the same way: its answer is the
 * rule failing closed, not the policies'. Beside `revision: null` the ids are as unconfirmed as the
 * revision — they name policies in whatever set the evaluator held. An id is
 * the policy's name as its producer documents it, never an index the engine
 * made up. The shape is {@link isReportablePolicyId}'s and the bound
 * {@link DETERMINING_POLICIES_MAX}; a rule builds the two keys with
 * {@link boundDeterminingPolicies}, which counts whatever does not fit in
 * `determiningPoliciesOmitted` — present only when it is not zero — so a rule
 * that uses it cannot trip the check.
 */
export type RuleEvaluation =
	| { readonly status: "not_invoked" }
	| ({ readonly status: "completed" } & EvaluatedRevision & DeterminingPolicies)
	| ({ readonly status: "failed" } & EvaluatedRevision);

/** Which policy snapshot an evaluated {@link RuleEvaluation} concerned. */
export type EvaluatedRevision =
	| { readonly revision: string }
	| { readonly revision: null; readonly loadedRevision?: string };

/**
 * The determining policies a completed {@link RuleEvaluation} may name (#199).
 * `determiningPoliciesOmitted` only ever stands beside `determiningPolicies`;
 * `evaluate()` refuses it alone. The type leaves both optional rather than
 * saying so, because the stricter union stops `{ status, revision }` with a
 * `"completed" | "failed"` status from type-checking — code that compiled
 * against the #244 type. {@link boundDeterminingPolicies} returns the pair in
 * the shape the check wants.
 */
export interface DeterminingPolicies {
	readonly determiningPolicies?: readonly string[];
	readonly determiningPoliciesOmitted?: number;
}

/**
 * The shape a policy revision reference is held to: `scheme:encoded`, the OCI
 * image-spec digest grammar. Enforced by `evaluate()` on everything a rule
 * reports, because what a rule reports reaches the wire and the audit log — a
 * path, a label with spaces or policy text does not fit it.
 */
export const POLICY_REVISION_PATTERN = /^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]+$/;

/** Longest reference carried. `sha512:` and its 128 hex characters is 135. */
export const POLICY_REVISION_MAX_LENGTH = 256;

/**
 * Most determining policies one evaluation lists (#199). Every decision's
 * audit line carries them, and so may its response: a handful answers "which
 * policy decided", and the rest are counted, not dropped. With
 * {@link POLICY_ID_MAX_LENGTH} this bounds one evaluation's ids at 4,096
 * UTF-16 units — about 4 KiB of ASCII, at most 12 KiB of UTF-8 — under the
 * 16 KiB a line-splitting log driver cuts at. That is one evaluation's; a
 * decision line carries one per reporting rule.
 */
export const DETERMINING_POLICIES_MAX = 32;

/**
 * Longest determining policy id carried, in UTF-16 code units (`String.length`,
 * so an astral character counts two) — a name, not a policy's text.
 */
export const POLICY_ID_MAX_LENGTH = 128;

/**
 * The code points a determining policy id may not hold, as inclusive ranges.
 * They break a log line (the C0 controls, DEL, the C1 controls, the line and
 * paragraph separators), reorder it (the bidi controls: the Arabic letter
 * mark, LRM and RLM, the embeddings and overrides, the isolates), or hide in
 * it so that an id displays as another (the soft hyphen, the Mongolian vowel
 * separator, the zero-width space, the word joiner and the invisible
 * operators, the byte order mark, the tag characters). The zero-width joiner
 * and non-joiner are allowed: Persian and Indic text and emoji need them.
 * Look-alike letters are not in scope — no range can rule them out. An id
 * must also be well-formed UTF-16 (no lone surrogate, which does not survive
 * a JSON round trip). Published so the wire contract can be checked against it.
 */
export const POLICY_ID_FORBIDDEN_RANGES: ReadonlyArray<readonly [number, number]> = Object.freeze([
	Object.freeze([0x0000, 0x001f] as const),
	Object.freeze([0x007f, 0x009f] as const),
	Object.freeze([0x00ad, 0x00ad] as const),
	Object.freeze([0x061c, 0x061c] as const),
	Object.freeze([0x180e, 0x180e] as const),
	Object.freeze([0x200b, 0x200b] as const),
	Object.freeze([0x200e, 0x200f] as const),
	Object.freeze([0x2028, 0x202e] as const),
	Object.freeze([0x2060, 0x2069] as const),
	Object.freeze([0xfeff, 0xfeff] as const),
	Object.freeze([0xe0000, 0xe007f] as const),
]);

/**
 * How a rule reports the {@link RuleEvaluation} behind one answer (#244).
 *
 * The evaluator makes one of these for **each invocation** of a rule and hands
 * it to `verify` / `decide`. The rule calls it at most once, before it
 * answers; `evaluate()` checks what was reported, freezes a copy and puts it on
 * that invocation's {@link RuleOutcome}.
 *
 * **Why a reporter, and not a richer answer.** An evaluation is a fact about
 * one invocation — one rule object answers concurrent decisions, so nothing
 * may be kept on the rule between them — which leaves two places for it: what
 * the rule returns, or something the evaluator hands in for that one call. A
 * richer return value (`{ passed, evaluation }`) fails **open** wherever the
 * evaluator does not know about it: an object is truthy, so an older copy of
 * core in a mixed install, or a composite rule calling `verify` itself, reads
 * every deny as a pass. A reporter fails the other way. An evaluator that
 * passes none gets the boolean it always got and merely records no evaluation
 * — which is what an absent `evaluation` already means: unknown.
 *
 * **What it is to the purity contract.** Not the side effect the contract
 * forbids. The reporter is the evaluator's own, made for this call and dead
 * after it; nothing reaches another invocation through it. What is reported is
 * part of the answer and is held to the same rule — equal attributes, equal
 * report — and the purity conformance suite compares it.
 *
 * Reporting twice in one invocation, or reporting something that does not
 * read, is a `TypeError` — thrown to the rule, and thrown again by `evaluate()`
 * after the rule answers, so a rule that swallows it still cannot produce a
 * decision that looks as if nothing had been reported. A report that arrives
 * after the answer is ignored: the decision is made.
 *
 * Optional in the signatures because a rule may be asked without one; a rule
 * that reports calls `report?.(…)`.
 */
export type ReportRuleEvaluation = (evaluation: RuleEvaluation) => void;

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
	/** `report` as on `Rule.verify` — see `ReportRuleEvaluation`. */
	decide(
		attrs: ReadonlyAttributes,
		signal: AbortSignal,
		report?: ReportRuleEvaluation,
	): Promise<boolean>;
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
