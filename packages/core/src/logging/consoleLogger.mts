// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Logger, LogLevel } from "./Logger.mjs";

/**
 * Ascending severity. A call is emitted when its level's rank is at least the
 * configured threshold's; `silent` sits above every level so nothing clears it.
 */
const LEVEL_RANK: Record<LogLevel, number> = {
	trace: 10,
	debug: 20,
	info: 30,
	warn: 40,
	error: 50,
	fatal: 60,
	silent: 70,
};

export interface ConsoleLoggerOptions {
	/**
	 * Minimum level to emit. Defaults to `"info"` so `trace` / `debug` never
	 * fire in production by accident. `"silent"` drops everything, which is
	 * what test harnesses want.
	 */
	readonly level?: LogLevel;
}

/**
 * Level routing (6 logger levels → 4 available `console.*` methods):
 *   trace → console.debug
 *   debug → console.debug
 *   info  → console.info
 *   warn  → console.warn
 *   error → console.error
 *   fatal → console.error
 *
 * The merged object (child bindings + per-call obj) is passed verbatim to the
 * underlying `console.*` method, which renders it with `util.inspect` — i.e.
 * human-readable text on stdout/stderr, not JSON. This logger is the
 * never-silent fallback for deployments that wire nothing; an aggregator-ready
 * NDJSON stream comes from injecting a structured logger instead (the
 * standalone template injects pino). Tests should spy on `console.*` and
 * assert on the call arguments rather than on string output.
 *
 * Per-call obj wins over child bindings on key collision (pino-compatible
 * last-write-wins).
 */
function emit(
	method: "debug" | "info" | "warn" | "error",
	bindings: Record<string, unknown>,
	obj: Record<string, unknown> | string,
	msg: string | undefined,
	args: unknown[],
): void {
	// console.* IS the sink here (this is the console-backed Logger
	// implementation); biome's recommended preset in this repo does not
	// enable `noConsole`, so no suppression is needed.
	if (typeof obj === "string") {
		// String-first has no per-call obj, so only the bindings could fill the
		// leading object — when they are empty too, prepending would render the
		// line as `{} message` (#133).
		const prefix = Object.keys(bindings).length > 0 ? [{ ...bindings }] : [];
		console[method](...prefix, obj, ...(msg !== undefined ? [msg] : []), ...args);
	} else {
		console[method]({ ...bindings, ...obj }, ...(msg !== undefined ? [msg] : []), ...args);
	}
}

/**
 * Create a `Logger` instance backed by `console.*`, optionally pre-bound with
 * the given `bindings`. Pass no argument to obtain a logger with no bindings
 * (equivalent to the exported `consoleLogger` singleton).
 */
export function createConsoleLogger(
	bindings: Record<string, unknown> = {},
	options: ConsoleLoggerOptions = {},
): Logger {
	const frozen = { ...bindings };
	const threshold = LEVEL_RANK[options.level ?? "info"];
	const enabled = (level: LogLevel): boolean => LEVEL_RANK[level] >= threshold;

	const logger: Logger = {
		trace(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("trace")) emit("debug", frozen, obj, msg, args);
		},
		debug(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("debug")) emit("debug", frozen, obj, msg, args);
		},
		info(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("info")) emit("info", frozen, obj, msg, args);
		},
		warn(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("warn")) emit("warn", frozen, obj, msg, args);
		},
		error(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("error")) emit("error", frozen, obj, msg, args);
		},
		fatal(obj: Record<string, unknown> | string, msg?: string, ...args: unknown[]) {
			if (enabled("fatal")) emit("error", frozen, obj, msg, args);
		},
		// The child inherits the threshold. A child that reverted to the default
		// would leak debug output from exactly the request-scoped loggers most
		// likely to carry request detail.
		child(extra) {
			return createConsoleLogger({ ...frozen, ...extra }, options);
		},
	};
	return logger;
}

/**
 * Pre-created root `Logger` (zero bindings) backed by `console.*`. Used as the
 * fallback when no structured logger is injected.
 */
export const consoleLogger: Logger = createConsoleLogger();
