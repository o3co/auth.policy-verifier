// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `CedarEngine` port an evaluator plugs into, the shapes of what it loads
 * and answers, and the registry engines are selected from. The registry lives
 * in one process-wide slot so that every copy of this package on the dependency
 * graph sees the same engines.
 */

import type { Logger } from "@o3co/auth.policy-verifier.core";
import type { CedarRequest } from "./mapping.mjs";
import type { PolicySource } from "./policySource.mjs";

/**
 * What one authorization call answered — Cedar's own `Response`, engine-neutral.
 *
 * `reason` is the determining policies' ids, and a decision records them as
 * `determiningPolicies` (#199), so an engine names its policies with
 * `namePolicies` and reads its evaluator's items as ids.
 * `errors` is rendered text rather than an evaluator's objects, because the
 * rule only logs it. What the rule *decides* on is whether each list is empty:
 * a non-empty `errors` is a deny whatever `decision` reads — see the
 * collector's answer table. Both must be lists; the rule fails an answer
 * whose either is not one.
 */
export interface CedarDecision {
	decision: "allow" | "deny";
	/**
	 * The ids of the determining policies (`10-permit-eng`) — what a
	 * decision's `determiningPolicies` names (#199). Empty: no policy
	 * determined the request — which only a `deny` can say: Cedar allows only
	 * on a permit, so an `allow` naming none is refused as not a decision
	 * (#283). An entry the engine cannot read as an id stays
	 * in the list — its emptiness decides an answer — as a string no id can be
	 * (one holding a control character), so the decision counts it in
	 * `determiningPoliciesOmitted` rather than naming it.
	 */
	reason: readonly string[];
	/**
	 * Evaluation errors, rendered: `policyId: message` from the wasm engine, the
	 * agent's own string, or the JSON of a structured error.
	 */
	errors: readonly string[];
	/**
	 * The revision of the policy set this answer was evaluated against, when
	 * the engine can vouch for it (#244) — the confirmation contract of the
	 * port. It is per answer, not per load, because that is the only moment the
	 * claim is true: a remote engine's set can be replaced or lost after `load`
	 * returned.
	 *
	 * An engine names `PolicySource.revision` here only if the answer provably
	 * came from the set compiled from that source. In-process that holds by
	 * construction. Over a network it holds when the evaluator itself reports
	 * what it evaluated — cedar-agent 0.2.x does not, so the http engine leaves
	 * this absent, and the collector reports the revision as not established
	 * rather than assuming the set it pushed at boot is still the one answering.
	 *
	 * Naming anything other than the loaded revision is an answer from a policy
	 * set this verifier did not load; the collector fails it closed.
	 */
	revision?: string;
	/**
	 * Present when the engine can tell this answer did **not** come from the
	 * set it loaded, though it cannot vouch for one that did (#283) — the http
	 * engine, whose agent names no revision but answers with the ids of the
	 * policies that determined it: an id it never pushed under this load's
	 * mark is somebody else's policy. The collector fails it closed and logs it
	 * as it logs a foreign revision. `reason` is then empty: another set's ids
	 * are not this verifier's to record. Any value other than `undefined` or
	 * `null` is taken as foreign — `false` included — so a malformed mark fails
	 * closed.
	 */
	foreign?: ForeignAnswer;
}

/**
 * Why an engine takes an answer for another set's (#283): a fixed label, and
 * the other load's mark when the id it could not place carried one — both
 * safe to log, since neither is text the evaluator chose.
 */
export interface ForeignAnswer {
	/**
	 * `"unknown policy"`: a determining policy this load never pushed.
	 * `"unreadable policy"`: an item that is no policy id at all — an agent
	 * reporting in a shape this engine does not read, which it cannot attribute.
	 */
	readonly why: "unknown policy" | "unreadable policy";
	/**
	 * Another load's mark, 16 hex — given only when the id is one of this
	 * load's own policy ids under a different mark: the same corpus, loaded
	 * from other files (a rolling deploy sharing the agent). It is what the
	 * other side spelled, unverified; an id that merely ends in `@` and 16 hex
	 * (a file may be named so) gives none.
	 */
	readonly mark?: string;
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
	 * Whether the policy sets this engine loads answer asynchronously — over
	 * I/O, out of process. Declared up front so the collector can refuse a
	 * configuration that is unsafe with such an engine (`onNoDeterminingPolicy
	 * = "abstain"`) before `load` has side effects; the set `load` returns must
	 * agree (`LoadedCedarPolicySet.async`), or the collector refuses it.
	 */
	readonly async: boolean;
	/**
	 * Whether every answer of this engine's policy sets names the revision it
	 * was evaluated against ({@link CedarDecision.revision}, #244). Declared up
	 * front for the reason `async` is: `requireConfirmedRevision` is refused at
	 * boot over an engine that does not, instead of denying every request once
	 * it is serving. Absent means `false`. The collector still checks each
	 * answer, so a declaration that turns out wrong denies rather than lies.
	 */
	readonly confirmsRevision?: boolean;
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
	 * that are its own (`endpoint`, `authentication`, `maxAnswerBytes` for the
	 * HTTP engine) and validates them here, at boot — the second boundary of
	 * two-boundary validation, since the config schema cannot know every
	 * engine's keys.
	 */
	readonly config: Readonly<Record<string, unknown>>;
	/** For what an operator should see at boot: which engine, where, how many policies. */
	readonly logger: Logger;
}

/**
 * The registry, in one process-wide slot rather than this module's own scope
 * (v0.10.0 audit). `cedar-wasm` registers into whichever copy of this package
 * it resolves; with two copies on the dependency graph, a module-scope map was
 * two registries, and a collector reading the other one never saw wasm and
 * fell through to the http engine — a different process deciding
 * authorization, with nothing failing. `Symbol.for` names the same slot from
 * every copy, so the refusal of a different engine under a taken name holds
 * across copies too.
 */
const ENGINES_SLOT = Symbol.for("@o3co/auth.policy-verifier.cedar#engines");
const slot = globalThis as unknown as Record<symbol, Map<string, CedarEngine> | undefined>;
slot[ENGINES_SLOT] ??= new Map<string, CedarEngine>();
const engines: Map<string, CedarEngine> = slot[ENGINES_SLOT];

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
