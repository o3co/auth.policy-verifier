// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Structured logger port for the policy verifier.
 *
 * The same shape as the `Logger` port in `@o3co/auth-provider-core`, so one
 * host logger serves the whole stack; a pino instance satisfies it without an
 * adapter. Not full pino parity: pino also takes an `Error` first argument and
 * printf-style interpolation through the trailing `...args`, which the
 * `unknown[]` rest admits for assignment compatibility but the default
 * `consoleLogger` does not interpret.
 *
 * The first argument is a structured object (the optional `msg` is then the
 * summary) or a plain string. Prefer object-first at security-relevant call
 * sites: the keys stay inspectable, which keeps field-path redaction (PII,
 * credentials) tractable.
 */

/**
 * The six emitting levels plus `silent`, which emits nothing.
 *
 * `silent` is a threshold value, not something a call site passes — there is no
 * `logger.silent(...)`.
 */
export type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "silent";

export interface Logger {
	// Two overload shapes mirror pino: object-first carries structured
	// bindings + optional message, string-first carries a printf-style
	// message + any extra arguments (forwarded verbatim by `consoleLogger`).
	trace(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	trace(msg: string, ...args: unknown[]): void;
	debug(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	debug(msg: string, ...args: unknown[]): void;
	info(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	info(msg: string, ...args: unknown[]): void;
	warn(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	warn(msg: string, ...args: unknown[]): void;
	error(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	error(msg: string, ...args: unknown[]): void;
	fatal(obj: Record<string, unknown>, msg?: string, ...args: unknown[]): void;
	fatal(msg: string, ...args: unknown[]): void;
	/**
	 * Return a child logger that prepends `bindings` to every subsequent log
	 * call. Per-call object fields win over child bindings on key collision
	 * (last-write-wins, mirroring pino).
	 */
	child(bindings: Record<string, unknown>): Logger;
}

/**
 * The narrow logger shape that injection seams accept.
 *
 * `Logger` is the interface this project logs *through*; `EventLogger` is the
 * one it *demands* of a caller. A host logger that omits `trace` / `fatal` /
 * `child` does not satisfy `Logger`; one whose methods take only an object
 * first — `EventLogger`'s own shape, message required or not — satisfies
 * neither `Logger` nor `Pick<Logger, "error">`: a picked method keeps both
 * overloads, and nothing of it matches the string-first one. Seams that only
 * emit a named structured event take this instead; use `Logger` where the full
 * surface is used.
 *
 * `info` is here because the per-decision audit line is written on the
 * successful path; without a non-failure level it would have to be `warn`,
 * and `warn` would stop meaning "something is wrong". The port asks only for
 * the three levels these seams use; the loggers a host passes (console, pino
 * and the like) have all three.
 */
export interface EventLogger {
	info(obj: Record<string, unknown>, msg: string): void;
	warn(obj: Record<string, unknown>, msg: string): void;
	error(obj: Record<string, unknown>, msg: string): void;
}
