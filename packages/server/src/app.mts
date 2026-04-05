import express from "express";
import {
	type AttributeCollector,
	AttributePipeline,
	type Module,
	type PathResolver,
	Registry,
	type ResourceParser,
	type RuleCollector,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import { createHealthcheckRouter } from "@o3co/auth.utils/express";
import type { AppConfig } from "./config/application.schema.mjs";
import { createVerifyRouter } from "./routes/verify.mjs";

export interface CreateAppOptions {
	pathResolver: PathResolver;
	config: AppConfig;
	modules: Module[];
}

export async function createApp(options: CreateAppOptions): Promise<express.Express> {
	const { pathResolver, config, modules } = options;

	// 1. Create registries
	const attributeCollectorRegistry = new Registry<AttributeCollector>();
	const ruleCollectorRegistry = new Registry<RuleCollector>();
	const resourceParserRegistry = new Registry<ResourceParser>();

	// 2. Initialize modules — each registers collectors/rules/parsers
	const context = {
		pathResolver,
		config: config as unknown as Record<string, unknown>,
		attributeCollectorRegistry,
		ruleCollectorRegistry,
		resourceParserRegistry,
	};

	for (const mod of modules) {
		await mod.init(context);
	}

	// 3. Resolve attribute collectors from config
	const attributeCollectors = config.attribute.collectors.map((entry) =>
		attributeCollectorRegistry.get(entry.collector),
	);

	// 4. Resolve rule collectors from config
	const ruleCollectors = config.rule.collectors.map((entry) =>
		ruleCollectorRegistry.get(entry.collector),
	);

	// 5. Resolve resource parser from config
	const resourceParser = resourceParserRegistry.get(config.resource.parser);

	// 6. Build Express app
	const app = express();
	const prefix = config.http.pathPrefix || "/";
	app.use(prefix, createHealthcheckRouter());
	app.use(
		prefix,
		createVerifyRouter({
			jwt: config.oauth.jwt,
			resourceParser,
			attributePipeline: new AttributePipeline(attributeCollectors),
			rulePipeline: new RulePipeline(ruleCollectors),
		}),
	);

	return app;
}
