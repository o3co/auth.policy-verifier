// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from "@o3co/auth.policy-verifier.core";
import type { CedarRequest } from "./mapping.mjs";
import type { PolicySource } from "./policySource.mjs";

/**
 * What one authorization call answered — Cedar's own `Response`, engine-neutral.
 *
 * `errors` is rendered text (`policyId: message`) rather than an evaluator's
 * error object, because the rule only ever logs it; what the rule *decides* on
 * is whether the list is empty. A non-empty list is a deny whatever `decision`
 * reads — see the collector's answer table.
 */
export interface CedarDecision {
	decision: "allow" | "deny";
	/** Ids of the determining policies. Empty: no policy determined the request. */
	reason: readonly string[];
	/** Evaluation errors, already rendered. */
	errors: readonly string[];
}

/** A compiled policy set that answers in-process, synchronously. */
export interface SyncCedarPolicySet {
	readonly async: false;
	/** Throws {@link CedarEngineError} when the call itself failed. */
	isAuthorized(request: CedarRequest): CedarDecision;
}

/** A compiled policy set that answers over I/O, under the rule's deadline. */
export interface AsyncCedarPolicySet {
	readonly async: true;
	/**
	 * `signal` aborts when the rule's time budget (`verify.ruleTimeoutMs`) is
	 * spent or the request is gone; an engine hands it to its transport.
	 * Rejects with {@link CedarEngineError} when the call itself failed.
	 */
	isAuthorized(request: CedarRequest, signal: AbortSignal): Promise<CedarDecision>;
}

/**
 * A loaded policy set. Which of the two an engine returns decides what kind of
 * rule the collector builds: a `Rule` (`verify`) for a synchronous set, an
 * `AsyncRule` (`decide`) for an asynchronous one. Config is identical either
 * way — the transport is the engine's business, not the deployment's.
 */
export type LoadedCedarPolicySet = SyncCedarPolicySet | AsyncCedarPolicySet;

/**
 * Raised by an engine when it could not do what it was asked: at `load`, a
 * policy set it cannot parse or compile (the message names the offending
 * source); at `isAuthorized`, a call that failed outright — as opposed to a
 * call that *answered*, evaluation errors included, which is a
 * {@link CedarDecision}. The collector turns the first into a boot error and
 * the second into a logged deny.
 */
export class CedarEngineError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "CedarEngineError";
	}
}

/**
 * The port a Cedar evaluator plugs into.
 *
 * `@o3co/auth.policy-verifier.cedar` owns everything up to this line: policy
 * loading, the attribute-to-entity mapping, the request, and the rule that
 * interprets the answer. What actually evaluates the policy set is an engine
 * behind this interface, and which engine a deployment runs is a deployment
 * decision — in-process wasm (`@o3co/auth.policy-verifier.cedar-wasm`) where
 * the policy set is small and the hop is not worth paying, an out-of-process
 * agent where it is (#225). Engines register themselves with
 * {@link registerCedarEngine}; the collector picks one by its config `engine`
 * key, or by preference when the key is absent.
 */
export interface CedarEngine {
	/** The registry key and the config value that selects it: `"wasm"`, `"http"`. */
	readonly name: string;
	/**
	 * Boot: parse-checks and compiles the policy set — or hands it to the
	 * process that will, which is why the result may be a promise. `source.files`
	 * carries each file separately so a syntax error can name the file that
	 * contains it. Throws or rejects with {@link CedarEngineError} to refuse the
	 * set: a broken policy set refuses to start, it does not serve denials, and
	 * the collector's factory awaits this so that holds for a remote engine too.
	 */
	load(
		source: PolicySource,
		context: CedarEngineLoadContext,
	): LoadedCedarPolicySet | Promise<LoadedCedarPolicySet>;
}

/** What the collector hands an engine at `load`, beside the policy set. */
export interface CedarEngineLoadContext {
	/**
	 * The collector's whole config entry, as written. An engine reads the keys
	 * that are its own (`endpoint`, `authentication` for the HTTP engine) and
	 * validates them here, at boot — the second boundary of two-boundary
	 * validation, since the config schema cannot know every engine's keys.
	 */
	readonly config: Readonly<Record<string, unknown>>;
	/** For what an operator should see at boot: which engine, where, how many policies. */
	readonly logger: Logger;
}

const engines = new Map<string, CedarEngine>();

/**
 * When config names no engine, the first of these that is registered wins.
 * In-process first: a deployment that imported the wasm package chose it.
 */
const PREFERENCE: readonly string[] = ["wasm", "http"];

/** Where a known engine name comes from, for the boot error that names it. */
const ENGINE_PACKAGES: Readonly<Record<string, string>> = {
	wasm: "@o3co/auth.policy-verifier.cedar-wasm",
};

/**
 * Registers an engine under its name. Called at module scope by the package
 * that ships the engine, so that importing that package is all a deployment
 * does to make the engine selectable — the same shape as the attribute key
 * reservation in `keys.mts`, for the same reason: it is then in place before
 * any collector of any package is constructed. Registering the same object
 * twice is a no-op; a different object under a taken name is refused, because
 * silently replacing an evaluator is how two copies of a package would fight
 * without anyone noticing.
 */
export function registerCedarEngine(engine: CedarEngine): void {
	if (typeof engine?.name !== "string" || engine.name.length === 0) {
		throw new Error("registerCedarEngine: an engine needs a non-empty name");
	}
	// Checked here, where the mistake is: registered from JavaScript, an
	// object without `load` would otherwise fail at the first collector's boot.
	if (typeof engine.load !== "function") {
		throw new Error(`registerCedarEngine: engine "${engine.name}" needs a load function`);
	}
	const existing = engines.get(engine.name);
	if (existing === engine) return;
	if (existing !== undefined) {
		throw new Error(
			`registerCedarEngine: a different engine is already registered as "${engine.name}"`,
		);
	}
	engines.set(engine.name, engine);
}

/** The names currently registered, in registration order. */
export function registeredCedarEngines(): readonly string[] {
	return [...engines.keys()];
}

/**
 * Resolves the engine a `CedarPolicyRuleCollector` will use.
 *
 * | config `engine` | result |
 * | --- | --- |
 * | absent | the first registered of `wasm`, `http` — so `wasm` whenever the wasm package is imported; an engine outside that list is only ever chosen by name |
 * | a registered name | that engine — an explicit choice wins over the preference |
 * | `"wasm"`, not imported | error naming `@o3co/auth.policy-verifier.cedar-wasm` |
 * | anything else | error listing what is registered |
 *
 * Throws a plain `Error`; the collector prefixes it as a config error.
 */
export function resolveCedarEngine(name?: unknown): CedarEngine {
	if (name === undefined) {
		for (const preferred of PREFERENCE) {
			const engine = engines.get(preferred);
			if (engine !== undefined) return engine;
		}
		if (engines.size > 0) {
			throw new Error(
				`none of the engines chosen by default (${PREFERENCE.join(", ")}) is registered — set engine to one of the registered ones${registeredHint()}`,
			);
		}
		throw new Error(
			`no Cedar engine is registered — import "${ENGINE_PACKAGES.wasm}" to evaluate in-process, or import a package that registers another engine (registerCedarEngine) and name it as engine${registeredHint()}`,
		);
	}
	if (typeof name !== "string" || name.length === 0) {
		throw new Error(`engine must be a non-empty string, got ${JSON.stringify(name)}`);
	}
	const engine = engines.get(name);
	if (engine !== undefined) return engine;
	const pkg = ENGINE_PACKAGES[name];
	if (pkg !== undefined) {
		throw new Error(
			`engine "${name}" is not registered — import "${pkg}", which registers it, before the app is built${registeredHint()}`,
		);
	}
	throw new Error(`engine "${name}" is not a registered Cedar engine${registeredHint()}`);
}

function registeredHint(): string {
	const names = registeredCedarEngines();
	return names.length === 0 ? " (none registered)" : ` (registered: ${names.join(", ")})`;
}
