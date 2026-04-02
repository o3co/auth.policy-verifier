import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import {
	type AttributeCollector,
	AttributePipeline,
	type ResourceParser,
	type RuleCollector,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	PayloadSubjectIdCollector,
	RequestContextCollector,
	StaticPermissionCollector,
	StaticRoleCollector,
	ResourceActionPermissionRuleCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.foundation";
import { createHealthcheckRouter } from "@o3co/auth.utils/express";
import { AppConfigSchema } from "./config/application.schema.mjs";
import { createVerifyRouter } from "./routes/verify.mjs";

// biome-ignore lint/suspicious/noExplicitAny: collector constructors accept varied config shapes
type CollectorClass = new (config: any) => AttributeCollector;
// biome-ignore lint/suspicious/noExplicitAny: collector constructors accept varied config shapes
type RuleCollectorClass = new (config: any) => RuleCollector;

const BUILTIN_COLLECTORS: Record<string, CollectorClass> = {
	PayloadScopeCollector,
	PayloadSubjectIdCollector,
	RequestContextCollector,
	StaticPermissionCollector,
	StaticRoleCollector,
};

const BUILTIN_RULE_COLLECTORS: Record<string, RuleCollectorClass> = {
	ResourceActionScopeRuleCollector,
	ResourceActionPermissionRuleCollector,
};

export interface PolicyVerifierOptions {
	configPath: string;
	collectors?: Record<string, CollectorClass>;
	ruleCollectors?: Record<string, RuleCollectorClass>;
	resourceParser?: ResourceParser;
}

export async function createApp(options: PolicyVerifierOptions): Promise<express.Express> {
	const config = validate(parseFile(options.configPath), AppConfigSchema);

	const collectorMap = { ...BUILTIN_COLLECTORS, ...options.collectors };
	const ruleCollectorMap = { ...BUILTIN_RULE_COLLECTORS, ...options.ruleCollectors };

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

	const resourceParser = options.resourceParser ?? new DotNotationResourceParser();

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
