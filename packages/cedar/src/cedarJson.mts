// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The Cedar JSON vocabulary a request is written in — declared here rather
 * than imported from `@cedar-policy/cedar-wasm`, so that the mapping depends on
 * Cedar's documented JSON formats and not on one evaluator's bindings. They
 * are the same shapes the wasm bindings and a Cedar agent's HTTP API accept,
 * so an engine passes a `CedarRequest` through unchanged; `cedar-wasm`
 * type-checks that structurally against the wasm declarations.
 */

/** An entity reference: `User::"alice"` is `{ type: "User", id: "alice" }`. */
export interface CedarEntityUid {
	type: string;
	id: string;
}

/**
 * One Cedar value in JSON form, including the `__entity` and `__extn` escapes.
 *
 * No `null`: Cedar has no null value, and its JSON formats refuse the token
 * outright ("JSON `null`s are not allowed in Cedar" — the whole request
 * fails, not the one attribute). An attribute that is `null` on our side is
 * therefore unrepresentable and is omitted by the mapping, like a function or
 * a fractional number; see `buildCedarRequest` for why omission is the safe
 * direction.
 */
export type CedarValue =
	| boolean
	| number
	| string
	| CedarValue[]
	| { [key: string]: CedarValue }
	| { __entity: CedarEntityUid }
	| { __extn: { fn: string; arg: CedarValue } | { fn: string; args: CedarValue[] } };

/** The request's `context` record. */
export type CedarContext = Record<string, CedarValue>;

/** One entity handed to the evaluator inline with the request. */
export interface CedarEntity {
	uid: CedarEntityUid;
	attrs: Record<string, CedarValue>;
	parents: CedarEntityUid[];
}
