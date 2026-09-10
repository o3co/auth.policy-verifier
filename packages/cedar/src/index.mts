// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { registerCedarEngine } from "./engine.mjs";
import { cedarHttpEngine } from "./httpEngine.mjs";

export type {
	CedarPolicyRuleCollectorConfig,
	CedarPolicyRuleCollectorOptions,
	NoDeterminingPolicy,
} from "./CedarPolicyRuleCollector.mjs";
export { CedarPolicyRuleCollector } from "./CedarPolicyRuleCollector.mjs";
export type { CedarContext, CedarEntity, CedarEntityUid, CedarValue } from "./cedarJson.mjs";
export type {
	AsyncCedarPolicySet,
	CedarDecision,
	CedarEngine,
	CedarEngineLoadContext,
	LoadedCedarPolicySet,
	SyncCedarPolicySet,
} from "./engine.mjs";
export {
	CedarEngineError,
	registerCedarEngine,
	registeredCedarEngines,
	resolveCedarEngine,
} from "./engine.mjs";
export type { CedarHttpEngineOptions } from "./httpEngine.mjs";
export {
	CEDAR_AUTHENTICATION_ENV,
	CEDAR_ENDPOINT_ENV,
	CEDAR_HTTP_ENGINE_NAME,
	CEDAR_LOAD_TIMEOUT_MS,
	cedarHttpEngine,
	createCedarHttpEngine,
	DEFAULT_CEDAR_ENDPOINT,
	entityUidLiteral,
} from "./httpEngine.mjs";
export {
	ATTR_REQUEST_ACTION,
	ATTR_REQUEST_RESOURCE_ID,
	ATTR_REQUEST_RESOURCE_RAW,
	ATTR_REQUEST_RESOURCE_TYPE,
	CEDAR_ATTRIBUTE_KEY_OWNER,
	CEDAR_ATTRIBUTE_KEYS,
} from "./keys.mjs";
export type { AttributeMapping, CedarRequest, EntityMappingConfig } from "./mapping.mjs";
export { CedarInputError } from "./mapping.mjs";
export { cedarPolicyModule } from "./module.mjs";
export type { PolicyFile, PolicySource } from "./policySource.mjs";
export { RequestFactsCollector } from "./RequestFactsCollector.mjs";

/*
 * The HTTP engine ships in this package and needs no evaluator, so it is
 * registered by importing this package — the fallback the selection table
 * lands on when no in-process engine was imported. Same shape, same reasoning
 * as the attribute key reservation in `keys.mts`.
 */
registerCedarEngine(cedarHttpEngine);
