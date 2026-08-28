// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

export { AttributePipeline } from "./AttributePipeline.mjs";
export type {
	CollectorLimits,
	CollectorPipeline,
	ResolvedCollectorLimits,
} from "./collectorLimits.mjs";
export {
	DEFAULT_COLLECT_DEADLINE_MS,
	DEFAULT_COLLECTOR_CONCURRENCY,
	DEFAULT_COLLECTOR_TIMEOUT_MS,
	resolveCollectorLimits,
} from "./collectorLimits.mjs";
export type { CollectorTimeoutDetail, CollectorTimeoutLimit } from "./errors.mjs";
export { AttributeConflictError, CollectorTimeoutError, ResourceParseError } from "./errors.mjs";
export type { EvaluateOptions } from "./evaluate.mjs";
export { evaluate } from "./evaluate.mjs";
export {
	ATTR_CLIENT_ID,
	ATTR_PERMISSIONS,
	ATTR_ROLES,
	ATTR_SCOPES,
	ATTR_USER_ID,
} from "./keys.mjs";
export type { ConsoleLoggerOptions } from "./logging/consoleLogger.mjs";
export { consoleLogger, createConsoleLogger } from "./logging/consoleLogger.mjs";
export type { EventLogger, Logger, LogLevel } from "./logging/Logger.mjs";
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
	CollectorRequest,
	Decision,
	DecisionReason,
	KeyResolver,
	ReadonlyAttributes,
	Resource,
	ResourceParser,
	Role,
	Rule,
	RuleCollector,
	RuleGroupOutcome,
	RuleOutcome,
	VerifierPayload,
} from "./types.mjs";
export type { UntrustedRequestContext } from "./untrusted.mjs";
export { markUntrustedRequestContext, readUntrustedRequestContext } from "./untrusted.mjs";
