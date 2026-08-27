// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
import { ATTR_SCOPES } from "@o3co/auth.policy-verifier.core";

/** Options accepted by `HasScope`. */
export interface HasScopeOptions {
	/**
	 * Opt in to treating a bare granted scope (one containing no `:`) as
	 * `read:<scope>` in addition to its literal value. Defaults to `false`.
	 *
	 * This exists only for deployments whose issuer emits bare resource names
	 * and that relied on the rewrite before it became opt-in. It is off by
	 * default because the rewrite invents an action the issuer never wrote:
	 * a token granted `project` is silently promoted to `read:project`.
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
 * normalized form of it:
 *
 * - `read:PROJECT` does **not** satisfy a `read:project` requirement.
 * - `read:project:restricted` is a value in its own right. It does not satisfy
 *   `read:project`, and `read:project` does not satisfy it. Nothing is split
 *   off at the second `:`; a scope the issuer deliberately narrowed must not
 *   collapse into the broader one.
 *
 * ## Bare-scope rewrite
 *
 * A granted scope carrying no `:` is compared literally unless
 * `{ allowBareScopeRewrite: true }` is passed, in which case it also matches
 * `read:<scope>`. Even then, only a scope with **no** `:` is ever rewritten —
 * a value such as `project:restricted` is left alone, because which of its
 * segments is the action is unknowable and guessing would over-grant.
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

	verify(attrs: Attributes): boolean {
		const scopes = (attrs.get(ATTR_SCOPES) as unknown[] | undefined) ?? [];
		if (!Array.isArray(scopes)) return false;
		return scopes.some((s) => typeof s === "string" && this.matchScope(s, this.scope));
	}

	private matchScope(granted: string, required: string): boolean {
		if (granted === required) return true;

		// The rewrite applies to bare scopes only. A granted scope that already
		// contains ":" is never re-interpreted: splitting it to guess an action
		// is what let "read:project:restricted" pass as "read:project".
		if (this.allowBareScopeRewrite && !granted.includes(":")) {
			return `read:${granted}` === required;
		}

		return false;
	}
}
