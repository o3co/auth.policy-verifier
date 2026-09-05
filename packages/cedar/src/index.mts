// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

export type {
	CedarPolicyRuleCollectorConfig,
	CedarPolicyRuleCollectorOptions,
	NoDeterminingPolicy,
} from "./CedarPolicyRuleCollector.mjs";
export { CedarPolicyRuleCollector } from "./CedarPolicyRuleCollector.mjs";
export {
	ATTR_REQUEST_ACTION,
	ATTR_REQUEST_RESOURCE_ID,
	ATTR_REQUEST_RESOURCE_RAW,
	ATTR_REQUEST_RESOURCE_TYPE,
	CEDAR_ATTRIBUTE_KEY_OWNER,
	CEDAR_ATTRIBUTE_KEYS,
} from "./keys.mjs";
export type { AttributeMapping, EntityMappingConfig } from "./mapping.mjs";
export { CedarInputError } from "./mapping.mjs";
export { cedarPolicyModule } from "./module.mjs";
export { RequestFactsCollector } from "./RequestFactsCollector.mjs";
