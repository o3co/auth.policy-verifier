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
	 * "expose"`). Absent by default, so a collector that logs its context
	 * cannot leak a live token. The one legitimate use is a project-side
	 * collector calling a downstream API *as the subject* (token forwarding or
	 * exchange). NEVER log this field.
	 */
	credential?: string;
	/**
	 * Cancellation for this collect, and the one field that is not a fact about
	 * the request. Always present: the pipeline supplies one per collector per
	 * decision.
	 *
	 * It aborts when this collector overruns its budget, when the pipeline
	 * overruns its end-to-end deadline, when a sibling collector has already
	 * failed the decision, or when the caller went away. Pass it to whatever
	 * this collector waits on (`fetch(url, { signal: context.signal })`, a
	 * driver's cancellation option). The pipeline abandons a collector that
	 * ignores it, but that collector's outbound call keeps running after the
	 * decision it belonged to is gone.
	 *
	 * It is a live handle on the request: a **collector** may hold it for the
	 * duration of `collect`; a **rule** must not carry it into `verify`. See
	 * AGENTS.md, "Collector / Rule / Attribute Contract".
	 */
	signal: AbortSignal;
}

/**
 * What a pipeline is handed: the request, without the per-collector `signal`
 * the pipeline itself supplies. That one belongs to the fan-out and aborts on
 * bounds a transport knows nothing about. `signal` here is the optional
 * *caller-side* cancellation (a client that hung up, an outer deadline); the
 * pipeline links it into its own, so aborting it cancels every collector in
 * flight.
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
 * a group), and `code` / `message` surface on deny. A rule grants unless it is
 * marked `restricts`.
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
	 * `true` for a rule that only narrows what the granting rules allow: it can
	 * deny a request and is never a reason to allow one. `evaluate()` counts
	 * only granting rules — every rule without this marker — when it asks
	 * whether any rule applied, so a request that only restricting rules apply
	 * to goes to `onEmptyRuleSet`. Only `true` restricts, and a `ruleType`
	 * group holds one kind or the other.
	 */
	readonly restricts?: true;
	/**
	 * Answers a boolean. `report` is there for a rule that fronts a policy
	 * evaluator — see `ReportRuleEvaluation`; every other rule ignores it.
	 */
	verify(attrs: ReadonlyAttributes, report?: ReportRuleEvaluation): boolean;
}

/**
 * How one invocation of the policy evaluator behind a rule went.
 *
 * A rule that fronts an evaluator (a Cedar policy set, an OPA bundle) fails
 * closed for reasons that are not a policy's: the request could not be built,
 * the engine did not answer, the evaluation raised errors. The status keeps an
 * audit record from naming a policy that never ran. XACML keeps the same two
 * things apart as `Decision` and `Status`.
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
 * for a completed one — which policies determined the answer. See
 * docs/extending.md, "Reporting the evaluation behind an answer".
 *
 * `revision` is a string only when the evaluator vouches for what it
 * **evaluated**. `null` is the explicit unknown: the evaluator ran, and what
 * it evaluated cannot be established. What the deployment *loaded* is then
 * carried apart, as `loadedRevision`, so a consumer reading `revision` cannot
 * take a snapshot nobody confirmed for one that was evaluated.
 *
 * A reference matches {@link POLICY_REVISION_PATTERN}: `sha256:<64 hex>` for a
 * content digest, the engine's own scheme otherwise. What it covers is its
 * producer's to document, and it is never a promise of replay: attributes,
 * mapping and evaluator version decide an answer too.
 *
 * `determiningPolicies` names the policies that determined a **completed**
 * answer: for an allow, the permits that applied; for a deny, the forbids that
 * did; an empty list when no policy applied. It is a set, in the order the
 * rule reports it, and absent when the rule does not know. An id is the
 * policy's name as its producer documents it, never an index the engine made
 * up; beside `revision: null` it is as unconfirmed as the revision. Each id
 * satisfies {@link isReportablePolicyId}, and at most
 * {@link DETERMINING_POLICIES_MAX} are listed; the reporter's
 * {@link ReportRuleEvaluation.boundDeterminingPolicies} builds both keys to
 * fit, counting the rest in `determiningPoliciesOmitted` (present only when it
 * is not zero), so a rule that uses it cannot trip the check.
 *
 * `not_invoked` carries no revision key of either kind and no determining
 * policies, and `failed` no determining policies, by type and by the check in
 * `evaluate()`, which refuses them however the value is reached (inherited or
 * through a getter included).
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
 * The determining policies a completed {@link RuleEvaluation} may name.
 * `determiningPoliciesOmitted` only ever stands beside `determiningPolicies`;
 * `evaluate()` refuses it alone. The type leaves both optional rather than
 * saying so, because the stricter union would stop `{ status, revision }` with
 * a `"completed" | "failed"` status from type-checking, and a rule written
 * against a core without determining policies may build its report that way.
 * A reporter's {@link ReportRuleEvaluation.boundDeterminingPolicies} returns
 * the pair in the shape the check wants ({@link BoundDeterminingPolicies}).
 */
export interface DeterminingPolicies {
	readonly determiningPolicies?: readonly string[];
	readonly determiningPoliciesOmitted?: number;
}

/**
 * Determining policies made to fit the contract of the core that checks them —
 * what {@link ReportRuleEvaluation.boundDeterminingPolicies} returns, ready to
 * spread into a completed report.
 */
export interface BoundDeterminingPolicies {
	readonly determiningPolicies: readonly string[];
	/** Every distinct name that was not listed; absent when there was none. */
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
 * Most determining policies one evaluation lists; the rest are counted, not
 * dropped. Every decision's audit line carries them, and so may its response.
 * With {@link POLICY_ID_MAX_LENGTH} this bounds one evaluation's ids at 4,096
 * UTF-16 units — about 4 KiB of ASCII, at most 12 KiB of UTF-8 — under the
 * 16 KiB a line-splitting log driver cuts at. A decision line carries one such
 * list per reporting rule.
 *
 * This, {@link POLICY_ID_MAX_LENGTH} and {@link POLICY_ID_FORBIDDEN_RANGES} are
 * the checking core's bounds, published to be read, not to be enforced by a
 * rule. A rule applies them through its reporter's
 * {@link ReportRuleEvaluation.boundDeterminingPolicies}, because in a mixed
 * install the copy of core its package imports is not the one that checks.
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
 * How a rule reports the {@link RuleEvaluation} behind one answer. See
 * docs/extending.md, "Reporting the evaluation behind an answer".
 *
 * The evaluator makes one of these for **each invocation** of a rule and hands
 * it to `verify` / `decide`: one rule object answers concurrent decisions, so
 * nothing may be kept on the rule between them. The rule calls it at most
 * once, before it answers; `evaluate()` checks what was reported, freezes a
 * copy and puts it on that invocation's {@link RuleOutcome}.
 *
 * A reporter rather than a richer return value: `{ passed, evaluation }` is
 * truthy, so an older core in a mixed install, or a composite rule calling
 * `verify` itself, would read every deny as a pass. An evaluator that passes
 * no reporter still gets the boolean, and records no evaluation: unknown.
 *
 * The reporter is made for this call and dead after it, so it is not the side
 * effect the purity contract forbids; what is reported is part of the answer
 * (equal attributes, equal report), and the purity conformance suite compares
 * it.
 *
 * Reporting twice in one invocation, or reporting something that does not
 * read, is a `TypeError` — thrown to the rule, and thrown again by `evaluate()`
 * after the rule answers, so a rule that swallows it still cannot produce a
 * decision that looks as if nothing had been reported. A report that arrives
 * after the answer is ignored.
 *
 * Optional in the signatures because a rule may be asked without one; a rule
 * that reports calls `report?.(…)`.
 */
export interface ReportRuleEvaluation {
	(evaluation: RuleEvaluation): void;
	/**
	 * Makes the policies an evaluator named fit the contract of the core that
	 * checks this report: each name once, in the order given, those
	 * {@link isReportablePolicyId} accepts, at most
	 * {@link DETERMINING_POLICIES_MAX} of them — and every other distinct name
	 * counted in `determiningPoliciesOmitted`, left out when there was none.
	 * That core never refuses what it returns. `names` is iterated once; its
	 * order is the caller's, so sort names whose order the engine does not
	 * keep stable, or two replicas record one decision two ways.
	 *
	 * On the reporter, and not imported, because the bounds that count are the
	 * checking core's (the server's), which in a mixed install can differ from
	 * the copy of core a rule's package depends on. It is absent on a reporter
	 * from a core that predates determining policies (which refuses the keys as
	 * unknown, failing every completed answer as the rule's fault) and on a
	 * plain-function reporter (a test's, or a composite rule's own). So a rule
	 * names determining policies only through it and reports the rest of the
	 * evaluation either way, spreading `...report?.boundDeterminingPolicies?.(names)`
	 * into the report (`...undefined` spreads nothing). A reporting package can
	 * then be upgraded ahead of the server it runs under, or behind it.
	 *
	 * @throws {TypeError} for one name passed bare — a string iterates by
	 *   character, and would come back as a list of letters.
	 */
	readonly boundDeterminingPolicies?: (
		names: Iterable<unknown> & object,
	) => BoundDeterminingPolicies;
}

/**
 * A rule whose answer comes from I/O — an out-of-process policy engine such as
 * Cedar over HTTP. It cannot be a {@link Rule}: `verify` is synchronous and,
 * by contract, does no I/O. Otherwise it is held to the same contract: the
 * same `ruleType` grouping, `code` / `message` on deny and reporting in the
 * decision's `reason`, and an answer that is a function of `attrs` alone: a
 * `CollectorContext` retained from collect time may no more be read here than
 * in `verify`, its `signal` and `credential` included (the purity conformance
 * suite checks `decide` exactly as it checks `verify`).
 *
 * `decide` runs under a deadline — `evaluate()`'s `ruleTimeoutMs`, or what is
 * left of its `evaluateDeadlineMs` when that is shorter; once the phase is
 * spent the rule is not started — and is handed a `signal` that aborts when
 * that deadline or the caller ends; pass it to `fetch`. A rule that does not
 * answer in time fails the decision as a deny of its own, `RuleTimeoutError`,
 * never as a pass. See docs/extending.md, "Writing an asynchronous rule".
 */
export interface AsyncRule {
	ruleType: string;
	code: string;
	message: string;
	/**
	 * The discriminant: what makes this an asynchronous rule. Explicit, as the
	 * policy-set union in cedar is, rather than read off the presence of
	 * `decide`, so a synchronous rule that happens to carry an unrelated
	 * `decide` method is not sent down the asynchronous path.
	 */
	readonly async: true;
	/** As on `Rule`: a rule that narrows what the granting rules allow. */
	readonly restricts?: true;
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

/** Whether `rule` only narrows what the granting rules allow: `restricts` is exactly `true`. */
export function isRestrictingRule(rule: AnyRule): boolean {
	return (rule as { restricts?: unknown }).restricts === true;
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
	 * What the rule reported about the evaluation behind this answer, checked
	 * and frozen by `evaluate()`. Absent when the rule reported none,
	 * which is every rule that has no policy source to identify: what decides
	 * for a TypeScript rule is the deployed code and its config.
	 */
	evaluation?: RuleEvaluation;
}

/**
 * How one rule group (`ruleType`) came out. Groups are the unit of
 * AND-evaluation, so this is the granularity at which "why" is answerable.
 *
 * `evaluated` is every rule that actually ran, in evaluation order. The group
 * is an OR, so a passing group stops at its first passing rule: `evaluated`
 * ends with that rule, which is also `satisfiedBy`, and alternatives after it
 * never ran and are not reported. A failing group ran every alternative, so
 * `evaluated` lists them all.
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
 * A bag, not a claim set: core names no field and reads no field. The
 * transport that admitted the request populates it (this repo's server
 * spreads a signature-verified JWT's claims into it), and collectors narrow
 * the values they promote, which is where claim vocabulary belongs. Read-only
 * because it is shared across every collector of a decision.
 */
export interface SubjectAttributes {
	readonly [key: string]: unknown;
}
