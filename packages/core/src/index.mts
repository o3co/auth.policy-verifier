// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

export { AttributePipeline } from "./AttributePipeline.mjs";
export { evaluate } from "./evaluate.mjs";
export {
	ATTR_CLIENT_ID,
	ATTR_PERMISSIONS,
	ATTR_ROLES,
	ATTR_SCOPES,
	ATTR_USER_ID,
} from "./keys.mjs";
export type {
	AttributeCollectorFactory,
	KeyResolverFactory,
	Module,
	ModuleContext,
	PathResolver,
	ResourceParserFactory,
	RuleCollectorFactory,
} from "./modules/index.mjs";
export { Registry } from "./modules/index.mjs";
export { RulePipeline } from "./RulePipeline.mjs";
export type {
	AttributeCollector,
	Attributes,
	CollectorContext,
	Decision,
	KeyResolver,
	Resource,
	ResourceParser,
	Role,
	Rule,
	RuleCollector,
	VerifierPayload,
} from "./types.mjs";
