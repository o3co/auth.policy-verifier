// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Structured logger port for the policy verifier.
 *
 * Pino-compatible for the call shapes in use here, and deliberately the same
 * shape as the `Logger` port in `@o3co/auth-provider-core` so one host logger
 * serves the whole stack. A pino instance satisfies this interface without an
 * adapter; consumers may inject any object exposing these six methods +
 * `child()`. Not full pino parity — pino additionally supports `Error` as the
 * first argument and printf-style interpolation via the trailing `...args`
 * (covered by the `unknown[]` rest below for assignment compatibility, but not
 * interpreted by the default `consoleLogger`).
 *
 * The first argument may be either a structured object or a plain string.
 * When an object is passed, structured fields are propagated by the
 * implementation; the optional second `msg` becomes the human-readable
 * summary. Object-first is preferred at security-relevant call sites: it makes
 * field-path-based redaction (PII, credentials) tractable, since the keys are
 * directly inspectable rather than embedded inside a format string.
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
 * one it is willing to *demand* of a caller. The difference matters at seams a
 * composition root wires by hand — a host logger that omits `trace` / `fatal`
 * / `child`, or whose methods require a message argument, cannot satisfy
 * `Logger`. Neither can it satisfy `Pick<Logger, "error">`: narrowing to one
 * method keeps that method's full two-overload shape, which is the part such a
 * logger fails.
 *
 * So seams that only ever emit a named structured event — `logger.error({ err },
 * "jwt_verification_unavailable")` — take this instead. `Logger` satisfies it,
 * and so does a leaner host logger. Use `Logger` where the full surface is
 * genuinely used; use this where the alternative is a caller who cannot pass
 * anything at all.
 */
export interface EventLogger {
	warn(obj: Record<string, unknown>, msg: string): void;
	error(obj: Record<string, unknown>, msg: string): void;
}
