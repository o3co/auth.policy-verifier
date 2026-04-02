// Engine

// Collectors
export {
	PayloadScopeCollector,
	PayloadSubjectIdCollector,
	RequestContextCollector,
	StaticPermissionCollector,
	StaticRoleCollector,
} from "./collectors/index.mjs";
export type {
	AttributeCollector,
	Attributes,
	CollectorContext,
	Decision,
	JwtPayload,
	Resource,
	ResourceParser,
	Role,
	Rule,
	RuleCollector,
	VerifierPayload,
} from "./engine/index.mjs";
export {
	ATTR_CLIENT_ID,
	ATTR_CLIENT_IP,
	ATTR_PERMISSIONS,
	ATTR_ROLES,
	ATTR_SCOPES,
	ATTR_USER_ID,
	AttributePipeline,
	evaluate,
	RulePipeline,
} from "./engine/index.mjs";
// Resource
export { DotNotationResourceParser } from "./resource/index.mjs";
// Rules
export {
	HasPermission,
	HasScope,
	ResourceActionPermissionRuleCollector,
	ResourceActionScopeRuleCollector,
} from "./rules/index.mjs";
// Server
export type { PolicyVerifierOptions, VerifyRouterConfig } from "./server/index.mjs";
export { createApp, createVerifyRouter } from "./server/index.mjs";
