// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { registerCedarEngine } from "@o3co/auth.policy-verifier.cedar";
import { cedarWasmEngine } from "./wasmEngine.mjs";

/*
 * Registered here, at module scope: importing this package is all a
 * deployment does to make `engine = "wasm"` — and the engine-less default —
 * resolve to the in-process evaluator. An import runs this module body to
 * completion before anything that imported it continues, and `createApp`
 * builds no collector until every module is initialized, so the registration
 * is in place before the first `CedarPolicyRuleCollector` is constructed. The
 * same shape, and the same reasoning, as cedar's attribute key reservation.
 */
registerCedarEngine(cedarWasmEngine);

export type { CedarWasmEngine } from "./wasmEngine.mjs";
export { CEDAR_WASM_ENGINE_NAME, cedarWasmEngine } from "./wasmEngine.mjs";
