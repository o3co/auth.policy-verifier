// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Server } from "node:http";
import type { Logger } from "@o3co/auth.policy-verifier.core";

/**
 * Graceful shutdown for the scaffolded server.
 *
 * ## Why this is in the template rather than a dependency
 *
 * It used to be `gracefulShutdown` from `@o3co/auth.utils@0.0.4`. For a
 * component every protected call waits on, "does SIGTERM wait for in-flight
 * decisions, and for how long?" has to be answerable from the code an operator
 * deploys — and it was answerable only by reading a pre-1.0 package no
 * contract here pinned. Reading it answered the question, and the answer was
 * the reason to move it: **there was no deadline**. `server.close()` waits
 * indefinitely, so one stuck decision meant the process never exited on its
 * own and the orchestrator's SIGKILL took it down mid-flight — the opposite of
 * a graceful shutdown, arriving only under the load that produces a stuck
 * request. The cleanup-failure path also wrote to `console.error`, one bare
 * line in a composition root that went to the trouble of wiring NDJSON (#107).
 *
 * `auth.provider`'s standalone template made the same move for the same
 * reasons (o3co/auth.provider#290); keeping the two composition roots
 * symmetric is what lets one aggregator pipeline serve the whole stack.
 *
 * ## The guarantees, stated
 *
 * 1. **SIGTERM and SIGINT** both start it; a second signal is ignored rather
 *    than starting a second cleanup over the first one's work.
 * 2. **New connections stop immediately** (`close`), and idle keep-alive
 *    sockets are released (`closeIdleConnections`) — they hold the server open
 *    with no request behind them, so a quiet server would otherwise wait out
 *    the whole deadline for nothing.
 * 3. **In-flight requests get `drainTimeoutMs`** (default 10s) to finish.
 * 4. **Past the deadline, remaining connections are cut**
 *    (`closeAllConnections`) and the process exits **non-zero** — an
 *    orchestrator that only ever sees `0` cannot tell a clean drain from one
 *    that ran out of time.
 * 5. **`cleanup` runs after draining, before exit**, logged through the app
 *    logger and reflected in the exit code. It is bounded by
 *    `cleanupTimeoutMs`, so a dispose that never settles cannot wedge the
 *    process the way an unbounded `await` did.
 * 6. **A `close` that fails is not reported as a clean drain.**
 *
 * Size `drainTimeoutMs` **below** the orchestrator's own kill grace period
 * (Kubernetes `terminationGracePeriodSeconds`, compose `stop_grace_period`,
 * both 30s by default) — the point is to close on our terms before SIGKILL
 * arrives on someone else's.
 */
export interface GracefulShutdownOptions {
	readonly logger: Logger;
	/** Release what the composition holds — caches, clients, key resolvers. */
	readonly cleanup?: () => void | Promise<void>;
	/** How long in-flight requests get before connections are cut. Default 10s. */
	readonly drainTimeoutMs?: number;
	/**
	 * How long `cleanup` gets before the shutdown gives up on it. Defaults to
	 * `drainTimeoutMs`, so the worst-case shutdown is the two budgets in
	 * sequence — size both against the orchestrator's grace period, not one.
	 */
	readonly cleanupTimeoutMs?: number;
	/** Injected in tests; defaults to `process.exit`. */
	readonly exit?: (code: number) => void;
	/** Injected in tests; defaults to `process.on`. */
	readonly onSignal?: (signal: NodeJS.Signals, handler: () => void) => void;
	/** Injected in tests; defaults to `process.removeListener`. */
	readonly offSignal?: (signal: NodeJS.Signals, handler: () => void) => void;
}

const DEFAULT_DRAIN_TIMEOUT_MS = 10_000;
const SIGNALS: readonly NodeJS.Signals[] = ["SIGTERM", "SIGINT"];

/**
 * Exit after yielding the loop once.
 *
 * `createAppLogger` uses pino's default destination, which is not synchronous,
 * so calling `process.exit` in the same tick as the last `logger.error` can
 * drop exactly the lines that say why the shutdown failed. One turn is a flush
 * window, not a guarantee: a deployment that needs certainty should pass an
 * `exit` that flushes its own transport first.
 */
export function deferExit(code: number, exitProcess: (code: number) => void = process.exit): void {
	setImmediate(() => exitProcess(code));
}

export function installGracefulShutdown(server: Server, options: GracefulShutdownOptions): void {
	const {
		logger,
		cleanup,
		drainTimeoutMs = DEFAULT_DRAIN_TIMEOUT_MS,
		exit = deferExit,
		onSignal = (signal, handler): void => {
			process.on(signal, handler);
		},
		offSignal = (signal, handler): void => {
			process.removeListener(signal, handler);
		},
	} = options;

	const cleanupTimeoutMs = options.cleanupTimeoutMs ?? drainTimeoutMs;

	let shuttingDown = false;
	let finished = false;

	/** Sentinel so a timed-out cleanup is reported as that, not as a throw. */
	const CLEANUP_TIMED_OUT = Symbol("cleanup-timed-out");

	/**
	 * Await `cleanup`, but not forever. `cleanup()` is invoked inside the async
	 * wrapper so a synchronous throw lands in the same rejection path as an
	 * async one.
	 */
	const runCleanup = async (): Promise<typeof CLEANUP_TIMED_OUT | undefined> => {
		if (!cleanup) return;
		let timer: ReturnType<typeof setTimeout> | undefined;
		try {
			return await Promise.race([
				(async (): Promise<undefined> => {
					await cleanup();
					return undefined;
				})(),
				new Promise<typeof CLEANUP_TIMED_OUT>((resolve) => {
					timer = setTimeout(() => resolve(CLEANUP_TIMED_OUT), cleanupTimeoutMs);
					timer.unref?.();
				}),
			]);
		} finally {
			if (timer) clearTimeout(timer);
		}
	};

	/** Run `cleanup` and exit. Called by whichever of drain / deadline wins. */
	const finish = async (code: number, reason: string): Promise<void> => {
		if (finished) return;
		finished = true;
		let exitCode = code;
		try {
			if ((await runCleanup()) === CLEANUP_TIMED_OUT) {
				logger.error({ cleanupTimeoutMs }, "graceful shutdown: cleanup timed out");
				exitCode = 1;
			}
		} catch (err) {
			// Through the app logger, not `console.error`: a shutdown that
			// failed to release what it held is exactly the line an operator
			// needs to find later, and a bare write is the one their pipeline
			// drops.
			logger.error({ err }, "graceful shutdown: cleanup failed");
			exitCode = 1;
		}
		logger.info({ reason, exitCode }, "graceful shutdown: complete");
		exit(exitCode);
	};

	const handler = (): void => {
		if (shuttingDown) return;
		shuttingDown = true;
		for (const signal of SIGNALS) offSignal(signal, handler);
		logger.info({ drainTimeoutMs }, "graceful shutdown: draining");

		const deadline = setTimeout(() => {
			logger.error(
				{ drainTimeoutMs },
				"graceful shutdown: drain deadline exceeded, closing remaining connections",
			);
			server.closeAllConnections();
			void finish(1, "drain-timeout");
		}, drainTimeoutMs);
		// The deadline must not be what keeps the process alive once the drain
		// has already finished.
		deadline.unref?.();

		server.close((err) => {
			clearTimeout(deadline);
			if (err) {
				// `close` reports through its callback — "Server is not running"
				// is the common one, but any listener teardown failure lands
				// here. Reporting "drained" and exiting 0 on it would tell an
				// orchestrator the shutdown went cleanly when the listener did
				// not actually come down.
				logger.error({ err }, "graceful shutdown: server close failed");
				void finish(1, "close-failed");
				return;
			}
			void finish(0, "drained");
		});
		// Idle keep-alive sockets have no request behind them, so nothing is
		// lost by releasing them — and without this a quiet server waits out
		// the whole deadline for connections that will never send anything.
		server.closeIdleConnections();
	};

	for (const signal of SIGNALS) onSignal(signal, handler);
}
