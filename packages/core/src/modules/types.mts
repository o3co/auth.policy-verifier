// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { AttributeCollector, ResourceParser, RuleCollector } from "../types.mjs";
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
/** Produces an `AttributeCollector` from its HOCON config entry. */
// biome-ignore lint/suspicious/noExplicitAny: collector constructors accept varied config shapes
export type AttributeCollectorFactory = (config: any) => AttributeCollector;
/** Produces a `RuleCollector` from its HOCON config entry. */
// biome-ignore lint/suspicious/noExplicitAny: rule collector constructors accept varied config shapes
export type RuleCollectorFactory = (config: any) => RuleCollector;
/** Produces a `ResourceParser` from its HOCON config entry. */
// biome-ignore lint/suspicious/noExplicitAny: resource parser constructors accept varied config shapes
export type ResourceParserFactory = (config: any) => ResourceParser;

/**
 * Context provided to each Module during initialization. Carries the registries
 * for the concepts core itself defines — collectors, rules, resource parsers.
 *
 * A host may carry more: the server extends this with its own registries (its
 * `ServerModuleContext` adds the JWT key-resolver registry) and initializes its
 * modules with the extended shape. A module written against the wider context
 * declares it via {@link Module}'s type parameter; one written against this
 * base shape runs under any host.
 */
export interface ModuleContext {
	pathResolver: PathResolver;
	config: Record<string, unknown>;
	attributeCollectorRegistry: Registry<AttributeCollectorFactory>;
	ruleCollectorRegistry: Registry<RuleCollectorFactory>;
	resourceParserRegistry: Registry<ResourceParserFactory>;
}

/**
 * A composable unit that registers collectors, rules, and parsers.
 * Modules are initialized asynchronously to allow dynamic imports via pathResolver.
 *
 * `C` is the context the module needs at `init`. The default is the base
 * {@link ModuleContext}; a module that registers into a host-specific registry
 * names that host's context instead (e.g. the server's
 * `builtinKeyResolversModule` is a `Module<ServerModuleContext>`), and can then
 * only be initialized by a host that supplies it. A `Module<ModuleContext>`
 * remains assignable wherever a wider context is provided.
 */
export interface Module<C extends ModuleContext = ModuleContext> {
	name: string;
	init(context: C): Promise<void>;
}
