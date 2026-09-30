// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The numeric knobs an operator sets on a config block: what each one admits,
 * and the one reader that admits it.
 *
 * Every such knob is absent (take the default), a number, or the string a HOCON
 * env substitution delivers. A value that is not a whole number in range must
 * be refused rather than passed to a library that ignores unusable options and
 * quietly applies its own default, and the rejection message has one shape.
 *
 * Both boundaries read a knob through this one function: `AppConfigSchema`
 * serves config files and the runtime resolvers serve the hand-built configs
 * `createApp` also accepts. See AGENTS.md, "Two-Boundary Config Validation".
 *
 * {@link NUMERIC_BOUNDS} is the whole table, here rather than beside each
 * consumer, and this module imports nothing but `config/defaults.mts`:
 * `AppConfigSchema` imports it to read config files, and `config/jwks.mts`,
 * `jwt/tokenAuthenticator.mts` and `routes/verify.mts` to read hand-built ones.
 * Anything it reached back for would arrive in every one of those, and a
 * config-only consumer of the schema must not end up with jose or express
 * behind a numeric bound.
 */

import {
	DEFAULT_BATCH_CONCURRENCY,
	DEFAULT_CLOCK_TOLERANCE_SECONDS,
	DEFAULT_COLLECT_DEADLINE_MS,
	DEFAULT_COLLECTOR_CONCURRENCY,
	DEFAULT_COLLECTOR_TIMEOUT_MS,
	DEFAULT_EVALUATE_DEADLINE_MS,
	DEFAULT_HTTP_PORT,
	DEFAULT_JWKS_CACHE_MAX_AGE_MS,
	DEFAULT_JWKS_COOLDOWN_MS,
	DEFAULT_JWKS_TIMEOUT_MS,
	DEFAULT_MAX_ACTION_LENGTH,
	DEFAULT_MAX_BATCH_SIZE,
	DEFAULT_MAX_BODY_BYTES,
	DEFAULT_MAX_CONTEXT_ENTRIES,
	DEFAULT_MAX_CONTEXT_VALUE_LENGTH,
	DEFAULT_MAX_RESOURCE_LENGTH,
	DEFAULT_MAX_TOKEN_AGE_SECONDS,
	DEFAULT_RULE_TIMEOUT_MS,
	MAX_CLOCK_TOLERANCE_SECONDS,
	MAX_TCP_PORT,
	MAX_TIMER_MS,
} from "./defaults.mjs";

/** How one numeric knob is read: what it defaults to and what it admits. */
export interface BoundSpec {
	/** Config key as the operator wrote it, e.g. `"jwksTimeoutMs"`. */
	field: string;
	/** Value taken when the key is absent. */
	fallback: number;
	/** Smallest accepted value. */
	minimum: number;
	/** Largest accepted value, for a knob bounded above; unbounded when omitted. */
	maximum?: number;
	/**
	 * Unit named in the rejection message, e.g. `"milliseconds"`. Omitted for a
	 * knob that counts nothing — a TCP port is a number, not a quantity of
	 * anything, and "between 1 and 65535 ports" reads as a mistake.
	 */
	unit?: string;
}

/**
 * Every numeric knob in the wire config, with the bound each one is held to at
 * both boundaries.
 *
 * The path an operator wrote is deliberately not here: the same knob is read at
 * more than one path (`resolveJwtTimeClaimBounds` sees `jwt` from the router and
 * `oauth.jwt` from `createApp`), so the path belongs to the calling boundary and
 * is passed to {@link resolveBound} rather than baked into the spec.
 */
export const NUMERIC_BOUNDS = {
	/**
	 * TCP port to bind. `0` is excluded on purpose even though `listen(0)`
	 * accepts it: it asks the OS for an arbitrary free port, which is unusable
	 * for a service the enforcement layer has to find.
	 */
	port: {
		field: "port",
		fallback: DEFAULT_HTTP_PORT,
		minimum: 1,
		maximum: MAX_TCP_PORT,
	},
	/**
	 * Abort a JWKS fetch after this long. Bounded above by what a timer can
	 * hold: Node clamps a `setTimeout` delay past 2^31 - 1 to ~1 ms, which
	 * would abort every fetch rather than none of them.
	 */
	jwksTimeoutMs: {
		field: "jwksTimeoutMs",
		fallback: DEFAULT_JWKS_TIMEOUT_MS,
		minimum: 1,
		maximum: MAX_TIMER_MS,
		unit: "milliseconds",
	},
	/**
	 * Minimum spacing between JWKS fetches. Zero is a valid cooldown — "refetch
	 * on every miss", at the cost of letting an attacker-chosen `kid` drive
	 * fetches at the provider — so the floor is 0 and the absent case is told
	 * apart by `undefined`, never by falsiness.
	 */
	jwksCooldownMs: {
		field: "jwksCooldownMs",
		fallback: DEFAULT_JWKS_COOLDOWN_MS,
		minimum: 0,
		unit: "milliseconds",
	},
	/** How long a fetched JWKS is served from cache. */
	jwksCacheMaxAgeMs: {
		field: "jwksCacheMaxAgeMs",
		fallback: DEFAULT_JWKS_CACHE_MAX_AGE_MS,
		minimum: 1,
		unit: "milliseconds",
	},
	/** Ceiling on `now - iat`. */
	maxTokenAgeSeconds: {
		field: "maxTokenAgeSeconds",
		fallback: DEFAULT_MAX_TOKEN_AGE_SECONDS,
		minimum: 1,
		unit: "seconds",
	},
	/**
	 * Skew allowance on every time-claim comparison. Zero is the default and a
	 * deliberate choice ("trust the clocks"), so the floor is 0 and the absent
	 * case is told apart by `undefined`, never by falsiness. Bounded above
	 * because tolerance lengthens every token's accepted life.
	 */
	clockToleranceSeconds: {
		field: "clockToleranceSeconds",
		fallback: DEFAULT_CLOCK_TOLERANCE_SECONDS,
		minimum: 0,
		maximum: MAX_CLOCK_TOLERANCE_SECONDS,
		unit: "seconds",
	},
	/** Cap on `POST /verify/batch` entries. */
	maxBatchSize: {
		field: "maxBatchSize",
		fallback: DEFAULT_MAX_BATCH_SIZE,
		minimum: 1,
		unit: "entries",
	},
	/*
	 * What one decision request may carry. Each has a floor of 1 and no ceiling:
	 * raising one is an operator's explicit statement about their own callers.
	 * `Infinity` and non-integers are refused as for every other knob.
	 */
	/** Cap on the JSON body `express.json()` will read. */
	maxBodyBytes: {
		field: "maxBodyBytes",
		fallback: DEFAULT_MAX_BODY_BYTES,
		minimum: 1,
		unit: "bytes",
	},
	/** Cap on the `resource` string. */
	maxResourceLength: {
		field: "maxResourceLength",
		fallback: DEFAULT_MAX_RESOURCE_LENGTH,
		minimum: 1,
		unit: "characters",
	},
	/** Cap on the `action` string. */
	maxActionLength: {
		field: "maxActionLength",
		fallback: DEFAULT_MAX_ACTION_LENGTH,
		minimum: 1,
		unit: "characters",
	},
	/** Cap on the properties and array elements in the whole `context` tree. */
	maxContextEntries: {
		field: "maxContextEntries",
		fallback: DEFAULT_MAX_CONTEXT_ENTRIES,
		minimum: 1,
		unit: "entries",
	},
	/** Cap on every string in the `context` tree, keys included. */
	maxContextValueLength: {
		field: "maxContextValueLength",
		fallback: DEFAULT_MAX_CONTEXT_VALUE_LENGTH,
		minimum: 1,
		unit: "characters",
	},
	/**
	 * How long one collector may take before it is cancelled. The floor is 1: a
	 * zero budget cancels every collector before it can answer, a verifier that
	 * denies everything. The ceiling is the timer's own: past 2^31 - 1, Node
	 * clamps the delay to ~1 ms, so a huge budget would be the zero budget.
	 */
	collectorTimeoutMs: {
		field: "collectorTimeoutMs",
		fallback: DEFAULT_COLLECTOR_TIMEOUT_MS,
		minimum: 1,
		maximum: MAX_TIMER_MS,
		unit: "milliseconds",
	},
	/**
	 * How long a whole collector fan-out may take. Not bounded below by
	 * `collectorTimeoutMs`: a deadline tighter than one collector's budget is
	 * legitimate (every stall is then reported as a deadline, a cruder message
	 * but a correct decision), and one `BoundSpec` cannot express a cross-knob
	 * rule. The ceiling is the timer's own, as for `collectorTimeoutMs`.
	 */
	collectorDeadlineMs: {
		field: "collectorDeadlineMs",
		fallback: DEFAULT_COLLECT_DEADLINE_MS,
		minimum: 1,
		maximum: MAX_TIMER_MS,
		unit: "milliseconds",
	},
	/**
	 * How long one asynchronous rule may take to answer: the same budget, and
	 * the same timer ceiling, as one collector.
	 */
	ruleTimeoutMs: {
		field: "ruleTimeoutMs",
		fallback: DEFAULT_RULE_TIMEOUT_MS,
		minimum: 1,
		maximum: MAX_TIMER_MS,
		unit: "milliseconds",
	},
	/**
	 * How long the whole rule phase may take — every asynchronous rule of one
	 * decision together. Groups run one after another, so a
	 * per-rule budget cannot bound the set; this is the rule side's twin of
	 * `collectorDeadlineMs`.
	 */
	evaluateDeadlineMs: {
		field: "evaluateDeadlineMs",
		fallback: DEFAULT_EVALUATE_DEADLINE_MS,
		minimum: 1,
		maximum: MAX_TIMER_MS,
		unit: "milliseconds",
	},
	/**
	 * How many collectors run at once, per pipeline, per decision. The floor is
	 * 1 rather than 0 for the reason `http.port`'s is: `0` is not "no limit", it
	 * is a fan-out that starts nothing and resolves with no attributes and no
	 * rules — a fail-open dressed as a setting.
	 */
	collectorConcurrency: {
		field: "collectorConcurrency",
		fallback: DEFAULT_COLLECTOR_CONCURRENCY,
		minimum: 1,
		unit: "collectors",
	},
	/**
	 * How many of a batch's entries are decided at once. The collector bounds
	 * above are per decision; without this one `POST /verify/batch` would
	 * multiply them by up to `maxBatchSize`. The floor is 1 for
	 * `collectorConcurrency`'s reason: `0` is not "no limit" but a batch that
	 * decides nothing.
	 */
	batchConcurrency: {
		field: "batchConcurrency",
		fallback: DEFAULT_BATCH_CONCURRENCY,
		minimum: 1,
		unit: "decisions",
	},
} satisfies Record<string, BoundSpec>;

/**
 * Renders a rejected value for an error message: quoted through `JSON.stringify`
 * for a string, so an empty or whitespace-only one is visible in the message,
 * and `String(...)` for everything else.
 *
 * `JSON.stringify` is deliberately *not* what renders the rest: it turns NaN and
 * Infinity into `null`, and a hand-built config can put either in a numeric slot.
 * Reporting `got null` for a value the caller wrote as `NaN` names something
 * they never wrote.
 */
export function describeValue(value: unknown): string {
	if (typeof value === "string") {
		return JSON.stringify(value);
	}
	if (value === null || typeof value !== "object") {
		return String(value);
	}
	return Array.isArray(value) ? "an array" : "an object";
}

/**
 * Phrases the accepted range the way the rejection message states it. A knob
 * bounded above names its endpoints, since "positive" says nothing about the
 * ceiling the operator just exceeded.
 */
function describeRange({ minimum, maximum, unit }: BoundSpec): string {
	if (maximum !== undefined) {
		const range = `an integer between ${minimum} and ${maximum}`;
		return unit === undefined ? range : `${range} ${unit}`;
	}
	const requirement = minimum > 0 ? "a positive integer" : "a non-negative integer";
	return unit === undefined ? requirement : `${requirement} number of ${unit}`;
}

/**
 * True for the two forms a knob is actually written in: a number, or the string
 * a HOCON env substitution delivers.
 *
 * A blank string is not one of them. `VAR=` substitutes an empty string and
 * `Number("")` is 0, so the knobs whose floor is 0 — `jwksCooldownMs`,
 * `clockToleranceSeconds` — would read a variable that was exported empty as a
 * deliberate zero. A zero cooldown is "refetch on every miss", which is the
 * fetch storm the knob exists to prevent. `http.callerAuth.token` refuses an
 * empty value for the same reason.
 */
function isWrittenAsNumber(value: unknown): value is number | string {
	return typeof value === "number" || (typeof value === "string" && value.trim() !== "");
}

/**
 * Reads one bound, coercing the string form on the way. Only numbers and
 * strings are coerced: `Number(true)` is 1 and `Number(null)` is 0, so running
 * anything else through `Number` would invent a bound the operator never wrote.
 * Non-integers, NaN and Infinity are refused for the same reason — a bound that
 * cannot be stated in whole units is a mistake, and `Infinity` is precisely the
 * unbounded case these knobs exist to prevent.
 *
 * @param path Config path of the block at the calling boundary, e.g.
 * `"oauth.jwt"`. It names the key the operator actually wrote, which is why it
 * is the boundary's to supply and not the spec's.
 */
export function resolveBound(value: unknown, spec: BoundSpec, path: string): number {
	if (value === undefined) {
		return spec.fallback;
	}
	const numeric = isWrittenAsNumber(value) ? Number(value) : Number.NaN;
	if (
		!Number.isInteger(numeric) ||
		numeric < spec.minimum ||
		(spec.maximum !== undefined && numeric > spec.maximum)
	) {
		throw new Error(
			`${path}.${spec.field} must be ${describeRange(spec)}, got ${describeValue(value)}`,
		);
	}
	return numeric;
}
