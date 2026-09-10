// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	checkParsePolicySet,
	type DetailedError,
	preparsePolicySet,
	statefulIsAuthorized,
} from "@cedar-policy/cedar-wasm/nodejs";
import {
	type CedarDecision,
	type CedarEngine,
	CedarEngineError,
	type CedarRequest,
	type PolicySource,
	type SyncCedarPolicySet,
} from "@o3co/auth.policy-verifier.cedar";

/** The name this engine registers under, and the config value that selects it. */
export const CEDAR_WASM_ENGINE_NAME = "wasm" as const;

/** The wasm engine's own type: it loads synchronously and answers synchronously. */
export interface CedarWasmEngine extends CedarEngine {
	readonly name: typeof CEDAR_WASM_ENGINE_NAME;
	load(source: PolicySource): SyncCedarPolicySet;
}

/** Distinguishes concurrently-loaded policy sets inside the one wasm instance. */
let policySetCounter = 0;

/**
 * The in-process Cedar engine: the official `@cedar-policy/cedar-wasm`
 * bindings behind the `CedarEngine` port.
 *
 * `load` parse-checks every file individually — so a syntax error names the
 * file that contains it — then compiles the concatenated set once, at boot,
 * into wasm memory under a per-load id. `isAuthorized` references that id per
 * request and re-parses nothing; the call is synchronous, deterministic, and a
 * few tens of microseconds, so the policy set answers as a plain `Rule`.
 *
 * What this engine costs is paid at import: the wasm module (about 12 MB on
 * disk) is instantiated when the bindings load. That is why it lives in its
 * own package — a deployment that evaluates out of process never carries it.
 */
export const cedarWasmEngine: CedarWasmEngine = {
	name: CEDAR_WASM_ENGINE_NAME,

	load(source: PolicySource): SyncCedarPolicySet {
		for (const file of source.files) {
			const answer = checkParsePolicySet({ staticPolicies: file.text });
			if (answer.type === "failure") {
				throw new CedarEngineError(`${file.source} failed to parse: ${details(answer.errors)}`);
			}
		}

		const policySetId = `auth.policy-verifier.cedar-wasm:${policySetCounter++}`;
		const compiled = preparsePolicySet(policySetId, { staticPolicies: source.text });
		if (compiled.type === "failure") {
			throw new CedarEngineError(
				`policy set from ${source.description} failed to compile: ${details(compiled.errors)}`,
			);
		}

		return {
			async: false,
			isAuthorized(request: CedarRequest): CedarDecision {
				const answer = statefulIsAuthorized({ ...request, preparsedPolicySetId: policySetId });
				if (answer.type !== "success") {
					throw new CedarEngineError(
						`cedar-wasm could not evaluate the request: ${details(answer.errors)}`,
					);
				}
				const { decision, diagnostics } = answer.response;
				return {
					decision,
					reason: diagnostics.reason,
					errors: diagnostics.errors.map((error) => `${error.policyId}: ${error.error.message}`),
				};
			},
		};
	},
};

function details(errors: DetailedError[]): string {
	return errors.map((error) => error.message).join("; ");
}
