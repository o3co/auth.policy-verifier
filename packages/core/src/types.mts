// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

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
 */
export interface CollectorContext {
	payload: VerifierPayload;
	resource: Resource;
	action: string;
	headers?: Record<string, string>;
	requestContext?: Record<string, unknown>;
}

/**
 * Map of attribute keys to values produced by attribute collectors.
 * Values are `unknown` so collectors can contribute any shape; downstream rules
 * are responsible for narrowing.
 */
export type Attributes = Map<string, unknown>;

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
 */
export interface Rule {
	ruleType: string;
	code: string;
	message: string;
	verify(attrs: Attributes): boolean;
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
 */
export interface RuleGroupOutcome {
	ruleType: string;
	passed: boolean;
	/**
	 * On a failing group, every rule in it — all of them ran and all of them
	 * failed. On a passing group, the single rule that satisfied it; the group is
	 * an OR, so evaluation stops at the first pass and the rest never ran.
	 */
	rules: RuleOutcome[];
}

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
	tokenType?: string;
	[key: string]: unknown;
}
