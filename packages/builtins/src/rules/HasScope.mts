// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `HasScope` rule: the token's scopes include a required scope, compared
 * exactly and case-sensitively — unless `allowBareScopeRewrite` is set, in
 * which case a granted scope with no `:` also matches `read:<scope>`.
 */

import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";
import { ATTR_SCOPES } from "@o3co/auth.policy-verifier.core";

/** Options accepted by `HasScope`. */
export interface HasScopeOptions {
	/**
	 * Opt in to treating a bare granted scope (one containing no `:`) as
	 * `read:<scope>` in addition to its literal value. Defaults to `false`.
	 *
	 * This exists only for deployments whose issuer emits bare resource names.
	 * It is off by default because the rewrite invents an action the issuer
	 * never wrote: a token granted `project` is silently promoted to
	 * `read:project`.
	 */
	allowBareScopeRewrite?: boolean;
}

/**
 * Rule that passes when the token carries the required scope.
 *
 * ## Matching
 *
 * Comparison is an **exact, case-sensitive string equality** against each value
 * in `ATTR_SCOPES`. OAuth 2.0 scope values are case-sensitive opaque strings
 * (RFC 6749 §3.3), so the verifier compares what the issuer wrote rather than a
 * normalized form of it: `read:PROJECT` does **not** satisfy `read:project`,
 * and `read:project:restricted` neither satisfies `read:project` nor is
 * satisfied by it — a scope the issuer deliberately narrowed must not collapse
 * into the broader one.
 *
 * ## Bare-scope rewrite
 *
 * A granted scope carrying no `:` is compared literally unless
 * `{ allowBareScopeRewrite: true }` is passed, in which case it also matches
 * `read:<scope>`. A scope containing `:`, such as `project:restricted`, is
 * never rewritten: which of its segments is the action is unknowable, and
 * guessing would over-grant.
 *
 * Non-string entries in `ATTR_SCOPES` never match and never throw: the map is
 * untyped, and a malformed value must produce a denial, not a crash.
 */
export class HasScope implements Rule {
	readonly ruleType = "scope";
	readonly code = "invalid_scope";
	readonly message: string;

	private readonly allowBareScopeRewrite: boolean;

	constructor(
		private scope: string,
		options?: HasScopeOptions,
	) {
		this.message = `Token does not have required scope: ${scope}`;
		this.allowBareScopeRewrite = options?.allowBareScopeRewrite ?? false;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const scopes: unknown = attrs.get(ATTR_SCOPES);
		if (!Array.isArray(scopes)) return false;
		return scopes.some((s) => typeof s === "string" && this.matchScope(s, this.scope));
	}

	private matchScope(granted: string, required: string): boolean {
		if (granted === required) return true;

		// The rewrite applies to bare scopes only. A granted scope that already
		// contains ":" is never re-interpreted: splitting it to guess an action
		// would let "read:project:restricted" pass as "read:project".
		if (this.allowBareScopeRewrite && !granted.includes(":")) {
			return `read:${granted}` === required;
		}

		return false;
	}
}
