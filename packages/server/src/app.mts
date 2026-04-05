import express from "express";
import {
	type AttributeCollectorFactory,
	AttributePipeline,
	type Module,
	type PathResolver,
	Registry,
	type ResourceParserFactory,
	type RuleCollectorFactory,
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

	// 1. Create registries (factories, not instances)
	const attributeCollectorRegistry = new Registry<AttributeCollectorFactory>();
	const ruleCollectorRegistry = new Registry<RuleCollectorFactory>();
	const resourceParserRegistry = new Registry<ResourceParserFactory>();

	// 2. Initialize modules — each registers factory functions
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

	// 3. Resolve attribute collectors from config — call factory with config entry
	const attributeCollectors = config.attribute.collectors.map((entry) => {
		const factory = attributeCollectorRegistry.get(entry.collector);
		return factory(entry);
	});

	// 4. Resolve rule collectors from config — call factory with config entry
	const ruleCollectors = config.rule.collectors.map((entry) => {
		const factory = ruleCollectorRegistry.get(entry.collector);
		return factory(entry);
	});

	// 5. Resolve resource parser from config
	const resourceParserFactory = resourceParserRegistry.get(config.resource.parser);
	const resourceParser = resourceParserFactory(config.resource);

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
