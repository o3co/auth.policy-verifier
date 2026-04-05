import type { AttributeCollector, ResourceParser, RuleCollector } from "../types.mjs";
import type { Registry } from "./Registry.mjs";

/**
 * Resolves a module specifier to a URL/path for dynamic import().
 * Typically set to import.meta.resolve at the application level.
 */
export type PathResolver = (specifier: string) => string;

/**
 * Context provided to each Module during initialization.
 */
export interface ModuleContext {
	pathResolver: PathResolver;
	config: Record<string, unknown>;
	attributeCollectorRegistry: Registry<AttributeCollector>;
	ruleCollectorRegistry: Registry<RuleCollector>;
	resourceParserRegistry: Registry<ResourceParser>;
}

/**
 * A composable unit that registers collectors, rules, and parsers.
 * Modules are initialized asynchronously to allow dynamic imports via pathResolver.
 */
export interface Module {
	name: string;
	init(context: ModuleContext): Promise<void>;
}
