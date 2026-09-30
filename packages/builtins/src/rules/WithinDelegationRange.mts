// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `WithinDelegationRange` rule: an entry of the token's delegation range
 * contains the requested path.
 */

import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";
import { ATTR_DELEGATION_RANGE, rangeContains } from "../delegation/range.mjs";

/**
 * Rule that passes when an entry of `ATTR_DELEGATION_RANGE` contains the
 * requested path, by the claims contract's containment rule (`rangeContains`).
 * A range that is absent, not a list, or holds no string that contains the
 * path fails, and so does a requested path outside the grammar, or none at
 * all — `null`, a request whose action is not one action of the grammar
 * (`requestedRangePath`). The range decides together with the policies,
 * never instead of them.
 */
export class WithinDelegationRange implements Rule {
	readonly ruleType = "delegation_range";
	readonly code = "outside_delegation_range";
	readonly message: string;

	constructor(private readonly path: string | null) {
		this.message =
			path === null
				? "Request is outside the token's delegation range: its action is not one action of the range grammar"
				: `Request is outside the token's delegation range: ${path}`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const path = this.path;
		if (path === null) return false;
		const range: unknown = attrs.get(ATTR_DELEGATION_RANGE);
		if (!Array.isArray(range)) return false;
		return range.some((entry) => typeof entry === "string" && rangeContains(entry, path));
	}
}
