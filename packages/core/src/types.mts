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
 * Abstract JWT key resolver. The concrete `key` type is determined by the
 * consuming JWT library (e.g. jose's `KeyObject | CryptoKey | Uint8Array | JWTVerifyGetKey`).
 * Core keeps it `unknown` so new algorithms can be introduced without touching core.
 */
export interface KeyResolver {
	key: unknown;
	algorithms: string[];
}

/**
 * Request-scoped input shared across every attribute and rule collector for a single verify call.
 *
 * Every field but one is input the deployment vouches for: `payload` survived
 * signature verification, `resource` and `action` were validated by the
 * transport, `headers` were set by it. `requestContext` is the caller's own —
 * see {@link UntrustedRequestContext} for why it is sealed rather than plain.
 */
export interface CollectorContext {
	payload: VerifierPayload;
	resource: Resource;
	action: string;
	headers?: Record<string, string>;
	/** Caller-supplied; read it with `readUntrustedRequestContext`. */
	requestContext?: UntrustedRequestContext;
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
	verify(attrs: ReadonlyAttributes): boolean;
}

/**
 * Produces rules for a request. A rule collector may return zero or more rules;
 * the `RulePipeline` flattens results from all collectors before evaluation.
 */
export interface RuleCollector {
	collect(context: CollectorContext): Promise<Rule[]>;
}

/** How one rule inside a group came out. */
export interface RuleOutcome {
	code: string;
	message: string;
	passed: boolean;
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
 * Decoded JWT claims consumed by the verifier, with an open index signature so
 * custom claims (e.g. `tenant`, `scope_*`) can be propagated without changing core.
 */
export interface VerifierPayload {
	sub?: string;
	azp?: string;
	scope?: string;
	iss?: string;
	aud?: string | string[];
	exp?: number;
	iat?: number;
	token?: string;
	/**
	 * The `Authorization` scheme the token arrived under, as the caller wrote it
	 * — `"Bearer"` (RFC 6750), whose casing is not normalized because it is
	 * reported, not compared.
	 *
	 * Not a claim, and not the accepted `typ` header: that one is a config value
	 * named `tokenType`, and this field carried the same name until #158. Two
	 * unrelated things called `tokenType` is a mistake a reader makes silently,
	 * so the one that is not a token type gave the name up.
	 *
	 * A consequence worth knowing when migrating: nothing writes `tokenType` on
	 * the payload any more. It used to be written over the spread claims, which
	 * silently discarded a token's own `tokenType` claim; such a claim now
	 * reaches the payload like any other. Whatever is read there is the token's,
	 * not the verifier's.
	 */
	authScheme?: string;
	[key: string]: unknown;
}
