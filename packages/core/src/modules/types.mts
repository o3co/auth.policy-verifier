import type { AttributeCollector, KeyResolver, ResourceParser, RuleCollector } from "../types.mjs";
import type { Registry } from "./Registry.mjs";

/**
 * Resolves a module specifier to a URL/path for dynamic import().
 * Typically set to import.meta.resolve at the application level.
 */
export type PathResolver = (specifier: string) => string;

/**
 * Factory functions that accept a config entry and return an instance.
 * Config entries come from the application HOCON config (e.g. { collector: "Name", ...extras }).
 */
// biome-ignore lint/suspicious/noExplicitAny: collector constructors accept varied config shapes
export type AttributeCollectorFactory = (config: any) => AttributeCollector;
// biome-ignore lint/suspicious/noExplicitAny: rule collector constructors accept varied config shapes
export type RuleCollectorFactory = (config: any) => RuleCollector;
// biome-ignore lint/suspicious/noExplicitAny: resource parser constructors accept varied config shapes
export type ResourceParserFactory = (config: any) => ResourceParser;
/**
 * Factory that produces a KeyResolver for a given JWT algorithm.
 * Async because some resolvers import PEM files or fetch JWKS metadata.
 */
// biome-ignore lint/suspicious/noExplicitAny: key resolver factories accept algorithm-specific config shapes
export type KeyResolverFactory = (config: any) => Promise<KeyResolver>;

/**
 * Context provided to each Module during initialization.
 */
export interface ModuleContext {
	pathResolver: PathResolver;
	config: Record<string, unknown>;
	attributeCollectorRegistry: Registry<AttributeCollectorFactory>;
	ruleCollectorRegistry: Registry<RuleCollectorFactory>;
	resourceParserRegistry: Registry<ResourceParserFactory>;
	keyResolverRegistry: Registry<KeyResolverFactory>;
}

/**
 * A composable unit that registers collectors, rules, and parsers.
 * Modules are initialized asynchronously to allow dynamic imports via pathResolver.
 */
export interface Module {
	name: string;
	init(context: ModuleContext): Promise<void>;
}
