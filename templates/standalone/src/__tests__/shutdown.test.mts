// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The contract of the template's graceful shutdown (`shutdown.ts`): a
 * force-close deadline, since `server.close()` waits for in-flight requests
 * indefinitely; failures logged through the app's own logger; and a non-zero
 * exit whenever the shutdown was not clean.
 */
import type { Server } from "node:http";
import type { Logger } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it, vi } from "vitest";
import { deferExit, installGracefulShutdown } from "../shutdown.js";

/** A `Server` double whose `close` callback fires only when we say so. */
function makeServer() {
	let closeCallback: ((err?: Error) => void) | undefined;
	const server = {
		close: vi.fn((cb?: (err?: Error) => void) => {
			closeCallback = cb;
			return server;
		}),
		closeIdleConnections: vi.fn(),
		closeAllConnections: vi.fn(),
	};
	return {
		server: server as unknown as Server,
		spies: server,
		finishDraining: () => closeCallback?.(),
		failClose: (err: Error) => closeCallback?.(err),
	};
}

/** A `Logger`-shaped spy, typed so a future port method cannot slip past. */
const makeLogger = () => {
	const spy = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(() => spy as unknown as Logger),
	};
	return spy satisfies Logger;
};

function install(opts: { cleanup?: () => void | Promise<void>; drainTimeoutMs?: number } = {}) {
	const { server, spies, finishDraining, failClose } = makeServer();
	const logger = makeLogger();
	const exit = vi.fn();
	const signals = new Map<string, () => void>();

	installGracefulShutdown(server, {
		logger,
		cleanup: opts.cleanup ?? (() => {}),
		...(opts.drainTimeoutMs === undefined ? {} : { drainTimeoutMs: opts.drainTimeoutMs }),
		exit,
		onSignal: (name, handler) => signals.set(name, handler),
		offSignal: (name) => signals.delete(name),
	});

	return { spies, logger, exit, signals, finishDraining, failClose };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

describe("installGracefulShutdown", () => {
	it("listens for both SIGTERM and SIGINT", () => {
		expect([...install().signals.keys()].sort()).toEqual(["SIGINT", "SIGTERM"]);
	});

	it("stops accepting connections and releases idle keep-alive sockets", () => {
		const { signals, spies } = install();
		signals.get("SIGTERM")?.();
		expect(spies.close).toHaveBeenCalledOnce();
		expect(spies.closeIdleConnections).toHaveBeenCalledOnce();
	});

	it("runs cleanup once draining completes, then exits zero", async () => {
		const cleanup = vi.fn();
		const { signals, finishDraining, exit } = install({ cleanup });
		signals.get("SIGTERM")?.();
		expect(cleanup).not.toHaveBeenCalled();
		finishDraining();
		await settle();
		expect(cleanup).toHaveBeenCalledOnce();
		expect(exit).toHaveBeenCalledWith(0);
	});

	it("ignores a second signal instead of running cleanup twice", async () => {
		const cleanup = vi.fn();
		const { signals, spies, finishDraining, exit } = install({ cleanup });
		const handler = signals.get("SIGTERM");
		handler?.();
		handler?.();
		finishDraining();
		await settle();
		expect(spies.close).toHaveBeenCalledOnce();
		expect(cleanup).toHaveBeenCalledOnce();
		expect(exit).toHaveBeenCalledOnce();
	});

	it("forces the remaining connections closed when draining outruns the deadline", () => {
		vi.useFakeTimers();
		try {
			const { signals, spies } = install({ drainTimeoutMs: 5_000 });
			signals.get("SIGTERM")?.();
			expect(spies.closeAllConnections).not.toHaveBeenCalled();
			vi.advanceTimersByTime(5_000);
			expect(spies.closeAllConnections).toHaveBeenCalledOnce();
		} finally {
			vi.useRealTimers();
		}
	});

	it("exits non-zero on a forced close, so the drain outcome is visible", async () => {
		vi.useFakeTimers();
		let exitSpy: ReturnType<typeof vi.fn>;
		try {
			const { signals, exit } = install({ drainTimeoutMs: 5_000 });
			exitSpy = exit;
			signals.get("SIGTERM")?.();
			vi.advanceTimersByTime(5_000);
		} finally {
			vi.useRealTimers();
		}
		await settle();
		expect(exitSpy).toHaveBeenCalledWith(1);
	});

	it("does not force-close a drain that finished in time", () => {
		vi.useFakeTimers();
		try {
			const { signals, spies, finishDraining } = install({ drainTimeoutMs: 5_000 });
			signals.get("SIGTERM")?.();
			finishDraining();
			vi.advanceTimersByTime(10_000);
			expect(spies.closeAllConnections).not.toHaveBeenCalled();
		} finally {
			vi.useRealTimers();
		}
	});

	it("reports a cleanup failure through the app logger, not console", async () => {
		const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
		const err = new Error("collector teardown failed");
		const { signals, finishDraining, logger, exit } = install({
			cleanup: () => Promise.reject(err),
		});
		signals.get("SIGTERM")?.();
		finishDraining();
		await settle();
		expect(logger.error).toHaveBeenCalledWith({ err }, expect.stringContaining("cleanup failed"));
		expect(consoleError).not.toHaveBeenCalled();
		expect(exit).toHaveBeenCalledWith(1);
		consoleError.mockRestore();
	});

	it("still exits when cleanup throws — a failed dispose must not wedge the process", async () => {
		const { signals, finishDraining, exit } = install({
			cleanup: () => {
				throw new Error("boom");
			},
		});
		signals.get("SIGTERM")?.();
		finishDraining();
		await settle();
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("does not report a failed close as a clean drain", async () => {
		const err = new Error("Server is not running");
		const { signals, failClose, logger, exit } = install();
		signals.get("SIGTERM")?.();
		failClose(err);
		await settle();
		expect(logger.error).toHaveBeenCalledWith({ err }, expect.stringContaining("close failed"));
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("bounds cleanup so a hanging dispose cannot wedge the process", async () => {
		// The drain deadline is already cleared when cleanup runs, so only the
		// cleanup budget stands between a dispose that never settles and an
		// `exit` that is never reached.
		vi.useFakeTimers();
		try {
			const { signals, finishDraining, exit, logger } = install({
				cleanup: () => new Promise<void>(() => {}),
				drainTimeoutMs: 5_000,
			});
			signals.get("SIGTERM")?.();
			finishDraining();
			await vi.advanceTimersByTimeAsync(5_000);
			expect(logger.error).toHaveBeenCalledWith(
				expect.objectContaining({ cleanupTimeoutMs: 5_000 }),
				expect.stringContaining("cleanup timed out"),
			);
			expect(exit).toHaveBeenCalledWith(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("does not penalise a cleanup that finishes inside its budget", async () => {
		vi.useFakeTimers();
		try {
			const { signals, finishDraining, exit } = install({
				cleanup: () => Promise.resolve(),
				drainTimeoutMs: 5_000,
			});
			signals.get("SIGTERM")?.();
			finishDraining();
			await vi.advanceTimersByTimeAsync(10_000);
			expect(exit).toHaveBeenCalledExactlyOnceWith(0);
		} finally {
			vi.useRealTimers();
		}
	});

	it("defers the real exit a turn so pino's buffered destination can flush (#210 review)", async () => {
		// `createAppLogger` uses pino's default (non-synchronous) destination, so
		// exiting in the same tick as the last `logger.error` can drop exactly the
		// `cleanup failed` line an operator would go looking for.
		const exitProcess = vi.fn();
		deferExit(3, exitProcess);
		expect(exitProcess).not.toHaveBeenCalled();
		await new Promise((resolve) => setImmediate(resolve));
		expect(exitProcess).toHaveBeenCalledWith(3);
	});

	it("reports the cleanup outcome as the reason, not the drain that preceded it", async () => {
		// `reason` names what decided the exit code, so the line an operator
		// alerts on never says "drained" beside a non-zero code. The drain
		// outcome is carried under its own key.
		const { signals, finishDraining, logger, exit } = install({
			cleanup: () => Promise.reject(new Error("teardown failed")),
		});
		signals.get("SIGTERM")?.();
		finishDraining();
		await settle();
		expect(logger.info).toHaveBeenCalledWith(
			{ reason: "cleanup-failed", drain: "drained", exitCode: 1 },
			"graceful shutdown: complete",
		);
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("keeps reason and drain identical when cleanup succeeds", async () => {
		const { signals, finishDraining, logger } = install({ cleanup: () => Promise.resolve() });
		signals.get("SIGTERM")?.();
		finishDraining();
		await settle();
		expect(logger.info).toHaveBeenCalledWith(
			{ reason: "drained", drain: "drained", exitCode: 0 },
			"graceful shutdown: complete",
		);
	});

	it("removes its own signal listeners once shutting down", () => {
		const { signals } = install();
		signals.get("SIGTERM")?.();
		expect(signals.size).toBe(0);
	});
});
