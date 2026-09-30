// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * This package's own attribute keys and their reservation in core's key
 * registry, made when this module is imported. The builtins write core's keys
 * (`scopes`, `userId`, …) and the operator's; the keys here are the ones whose
 * meaning is this package's — not core vocabulary (AGENTS.md "Core Vocabulary
 * Scope"), and not the operator's to write with a mapping.
 */

import { reserveAttributeKeys } from "@o3co/auth.policy-verifier.core";

/**
 * The paths of a delegated token's range, as a `string[]`. The delegation
 * range is not core vocabulary — its grammar and containment rule are this
 * stack's, not a standard's — so the builtins own the key.
 */
export const ATTR_DELEGATION_RANGE = "delegationRange" as const;

/** The npm package name this vocabulary is reserved under. */
export const BUILTINS_ATTRIBUTE_KEY_OWNER = "@o3co/auth.policy-verifier.builtins" as const;

/*
 * Reserved at module scope, beside the constant, so that the reservation is
 * in place before any collector can be constructed. With it,
 * `RequestContextAttributeCollector` and `PayloadClaimAttributeCollector`
 * refuse a mapping onto the key: `AttributePipeline` unions list keys, so a
 * mapping would add paths of its own to the range `DelegationRangeCollector`
 * read, and a narrowing would become a widening.
 */
reserveAttributeKeys({
	owner: BUILTINS_ATTRIBUTE_KEY_OWNER,
	keys: [ATTR_DELEGATION_RANGE],
	reason:
		"a delegated token's range, written by DelegationRangeCollector from the verified subject and read by WithinDelegationRange",
});
