import { resolve } from "node:path";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import { PayloadScopeCollector } from "#/collectors/PayloadScopeCollector.mjs";
import { PayloadSubjectIdCollector } from "#/collectors/PayloadSubjectIdCollector.mjs";
import { StaticPermissionCollector } from "#/collectors/StaticPermissionCollector.mjs";
import { StaticRoleCollector } from "#/collectors/StaticRoleCollector.mjs";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { AttributePipeline } from "#/engine/AttributePipeline.mjs";
import { RulePipeline } from "#/engine/RulePipeline.mjs";
import type { AttributeCollector, ResourceParser, RuleCollector } from "#/engine/types.mjs";
import { DotNotationResourceParser } from "#/resource/DotNotationResourceParser.mjs";
import { ResourceActionPermissionRuleCollector } from "#/rules/ResourceActionPermissionRuleCollector.mjs";
import { ResourceActionScopeRuleCollector } from "#/rules/ResourceActionScopeRuleCollector.mjs";
import { createHealthcheckRouter } from "./routes/healthcheck.mjs";
import { createVerifyRouter } from "./routes/verify.mjs";

// biome-ignore lint/suspicious/noExplicitAny: collector constructors accept varied config shapes
type CollectorClass = new (config: any) => AttributeCollector;
// biome-ignore lint/suspicious/noExplicitAny: collector constructors accept varied config shapes
type RuleCollectorClass = new (config: any) => RuleCollector;

const BUILTIN_COLLECTORS: Record<string, CollectorClass> = {
	PayloadScopeCollector,
	PayloadSubjectIdCollector,
	StaticPermissionCollector,
	StaticRoleCollector,
};

const BUILTIN_RULE_COLLECTORS: Record<string, RuleCollectorClass> = {
	ResourceActionScopeRuleCollector,
	ResourceActionPermissionRuleCollector,
};

export interface PolicyVerifierOptions {
	collectors?: Record<string, CollectorClass>;
	ruleCollectors?: Record<string, RuleCollectorClass>;
	resourceParser?: ResourceParser;
}

export async function createApp(options?: PolicyVerifierOptions): Promise<express.Express> {
	const confPath = resolve(import.meta.dirname, "../../config/application.conf");
	const config = validate(parseFile(confPath), AppConfigSchema);

	const collectorMap = { ...BUILTIN_COLLECTORS, ...options?.collectors };
	const ruleCollectorMap = { ...BUILTIN_RULE_COLLECTORS, ...options?.ruleCollectors };

	const attributeCollectors = config.attribute.collectors.map((entry) => {
		const Cls = collectorMap[entry.collector];
		if (!Cls) {
			throw new Error(`Unknown attribute collector: "${entry.collector}"`);
		}
		return new Cls(entry);
	});

	const ruleCollectors = config.rule.collectors.map((entry) => {
		const Cls = ruleCollectorMap[entry.collector];
		if (!Cls) {
			throw new Error(`Unknown rule collector: "${entry.collector}"`);
		}
		return new Cls(entry);
	});

	const resourceParser = options?.resourceParser ?? new DotNotationResourceParser();

	const app = express();
	app.use(config.http.pathPrefix, createHealthcheckRouter());
	app.use(
		config.http.pathPrefix,
		createVerifyRouter({
			jwt: config.oauth.jwt,
			resourceParser,
			attributePipeline: new AttributePipeline(attributeCollectors),
			rulePipeline: new RulePipeline(ruleCollectors),
		}),
	);

	return app;
}
