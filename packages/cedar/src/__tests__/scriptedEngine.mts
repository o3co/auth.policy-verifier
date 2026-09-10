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

export function scriptedEngine(name: string, async: boolean): ScriptedEngine {
	const engine: ScriptedEngine = {
		name,
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
						return engine.answer(request);
					},
				};
			}
			return {
				async: true,
				async isAuthorized(request, signal) {
					engine.requests.push(request);
					return engine.answer(request, signal);
				},
			};
		},
	};
	return engine;
}
