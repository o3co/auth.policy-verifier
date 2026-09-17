// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * A `CedarEngine` for this package's own tests: it evaluates nothing. What it
 * proves is the port — that the collector hands an engine the loaded policy
 * set, hands its policy set the request built from `attrs`, and turns the
 * answer into a rule outcome by the documented table, for a synchronous and
 * an asynchronous engine alike. The real evaluator is pinned end to end in
 * `packages/cedar-wasm`.
 */

import {
	type CedarDecision,
	type CedarEngine,
	CedarEngineError,
	type CedarRequest,
	type LoadedCedarPolicySet,
	type PolicySource,
} from "../index.mjs";

export type Answer = (request: CedarRequest, signal?: AbortSignal) => CedarDecision;

export interface ScriptedEngineOptions {
	/**
	 * Whether the engine vouches for what it evaluated (#244), the way the wasm
	 * engine does: it declares `confirmsRevision`, and an answer that names no
	 * revision of its own is stamped with the loaded source's. A case that needs
	 * an answer to arrive unvouched, or vouching for something else, says so in
	 * the answer itself (`revision: undefined` is left alone only when the key is
	 * present — see `load`).
	 */
	confirmsRevision?: boolean;
}

export interface ScriptedEngine extends CedarEngine {
	/** Every policy source `load` received, in order. */
	loads: PolicySource[];
	/** What the loaded policy set answers; tests replace it per case. */
	answer: Answer;
	/** The requests `isAuthorized` received, in order. */
	requests: CedarRequest[];
}

export const ALLOW: CedarDecision = { decision: "allow", reason: ["policy0"], errors: [] };
export const FORBIDDEN: CedarDecision = { decision: "deny", reason: ["policy1"], errors: [] };
export const UNDETERMINED: CedarDecision = { decision: "deny", reason: [], errors: [] };

/** A parse error the engine reports the way the wasm engine does — naming the file. */
const UNPARSEABLE = "permit(when;";

export function scriptedEngine(
	name: string,
	async: boolean,
	options: ScriptedEngineOptions = {},
): ScriptedEngine {
	const confirmsRevision = options.confirmsRevision ?? false;
	/** Stamps the loaded revision on an answer that does not mention one at all. */
	const vouch = (answer: CedarDecision, source: PolicySource): CedarDecision =>
		confirmsRevision && !("revision" in answer) ? { ...answer, revision: source.revision } : answer;
	const engine: ScriptedEngine = {
		name,
		async,
		confirmsRevision,
		loads: [],
		requests: [],
		answer: () => ALLOW,
		load(source: PolicySource): LoadedCedarPolicySet {
			for (const file of source.files) {
				if (file.text.includes(UNPARSEABLE)) {
					throw new CedarEngineError(`${file.source} failed to parse: unexpected token`);
				}
			}
			engine.loads.push(source);
			if (!async) {
				return {
					async: false,
					isAuthorized(request) {
						engine.requests.push(request);
						return vouch(engine.answer(request), source);
					},
				};
			}
			return {
				async: true,
				async isAuthorized(request, signal) {
					engine.requests.push(request);
					return vouch(engine.answer(request, signal), source);
				},
			};
		},
	};
	return engine;
}
