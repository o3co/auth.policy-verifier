// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The read-back of cedar-agent's policy set (#286), on its own: what a check
 * reads, what it makes of the set the agent holds, when it pushes this load's
 * set again, and when it runs at all. The engine's wiring of it is pinned in
 * `httpEngine.test.mts`; the agent's own behaviour — its PUT answer and a
 * later GET byte-identical, a token holder's edits showing in the GET, a
 * restart coming back empty — was checked against a real cedar-agent 0.2.2.
 */

import type { Logger } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it, vi } from "vitest";
import { type AgentPolicySet, agentPolicySetOf, createAgentReadBack } from "../agentReadBack.mjs";

const MARK = "@0123456789abcdef";
const OTHER_MARK = "@fedcba9876543210";

/** This load's set as the agent re-printed it. */
const PUSHED: AgentPolicySet = new Map([
	[`10-permit${MARK}`, "permit(\n  principal,\n  action,\n  resource\n);"],
	[`20-forbid${MARK}`, "forbid(\n  principal,\n  action,\n  resource\n);"],
]);

function logger(): Logger {
	const log = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: (): Logger => log,
	} as Logger;
	return log;
}

/** A promise and the functions that settle it — to hold a push open. */
function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (reason: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

function readBack(
	held: () => AgentPolicySet | Promise<AgentPolicySet>,
	push: () => Promise<AgentPolicySet> = async () => PUSHED,
) {
	let clock = 1_000_000;
	const log = logger();
	const read = vi.fn(async () => held());
	const pushed = vi.fn(push);
	const check = createAgentReadBack({
		pushed: PUSHED,
		ownMark: MARK,
		intervalMs: 30_000,
		now: () => clock,
		read,
		push: pushed,
		logger: log,
		fields: { engine: "http", endpoint: "http://127.0.0.1:8180" },
	});
	return {
		check,
		read,
		push: pushed,
		log,
		/** Moves the clock on — by an interval, by default. */
		tick: (ms = 30_000) => {
			clock += ms;
		},
	};
}

const errorLines = (log: Logger) =>
	(log.error as ReturnType<typeof vi.fn>).mock.calls.map(([, message]) => message);

describe("agentPolicySetOf — the agent's answer to PUT and GET /v1/policies", () => {
	it("reads a list of { id, content } as the set, by id", () => {
		expect(
			agentPolicySetOf([
				{ id: "a", content: "x" },
				{ id: "b", content: "y" },
			]),
		).toEqual(
			new Map([
				["a", "x"],
				["b", "y"],
			]),
		);
		expect(agentPolicySetOf([])).toEqual(new Map());
	});

	it.each([
		["not a list", { id: "a", content: "x" }],
		["an item without content", [{ id: "a" }]],
		["an id that is not a string", [{ id: 1, content: "x" }]],
		["an item that is not an object", ["a"]],
		// The agent holds one policy per id: two under one id is not its set.
		[
			"one id twice",
			[
				{ id: "a", content: "x" },
				{ id: "a", content: "y" },
			],
		],
	])("reads %s as no set at all", (_label, body) => {
		expect(agentPolicySetOf(body)).toBeUndefined();
	});
});

describe("createAgentReadBack — when it reads the agent's set back", () => {
	it("reads nothing within an interval of the push, and once when one has passed", async () => {
		const { check, read, tick } = readBack(() => PUSHED);
		expect(check.poll()).toBeUndefined();
		tick(29_999);
		expect(check.poll()).toBeUndefined();
		tick(1);
		await check.poll();
		expect(read).toHaveBeenCalledTimes(1);
		// The interval runs from the check just made.
		expect(check.poll()).toBeUndefined();
	});

	it("runs one check at a time, however many answers ask while it is out", async () => {
		const reading = deferred<AgentPolicySet>();
		const { check, read, tick } = readBack(() => reading.promise);
		tick();
		const first = check.poll();
		tick();
		expect(check.poll()).toBe(first);
		reading.resolve(PUSHED);
		await first;
		expect(read).toHaveBeenCalledTimes(1);
	});
});

describe("createAgentReadBack — what it makes of the set the agent holds", () => {
	it("answers on while the agent holds this load's set as pushed", async () => {
		const { check, push, tick } = readBack(() => new Map(PUSHED));
		tick();
		await check.poll();
		expect(check.altered).toBe(false);
		expect(push).not.toHaveBeenCalled();
	});

	it.each([
		[
			"a policy rewritten under its own id",
			new Map([...PUSHED, [`10-permit${MARK}`, "permit(principal, action, resource);"]]),
			{ changed: 1, missing: 0, added: 0 },
		],
		[
			"a policy deleted",
			new Map([[`10-permit${MARK}`, PUSHED.get(`10-permit${MARK}`)]]),
			{
				changed: 0,
				missing: 1,
				added: 0,
			},
		],
		[
			"a policy added under this load's mark",
			new Map([...PUSHED, [`evil${MARK}`, "permit(p, a, r);"]]),
			{
				changed: 0,
				missing: 0,
				added: 1,
			},
		],
		["nothing — an agent restarted", new Map(), { changed: 0, missing: 2, added: 0 }],
	])(
		"refuses while the agent holds %s, and pushes this load's set again",
		async (_label, held, difference) => {
			const pushing = deferred<AgentPolicySet>();
			const { check, push, log, tick } = readBack(
				() => held as AgentPolicySet,
				() => pushing.promise,
			);
			tick();
			const checking = check.poll();
			await vi.waitFor(() => expect(push).toHaveBeenCalledTimes(1));
			// Refused from the moment the difference is seen until the push lands.
			expect(check.altered).toBe(true);
			expect(log.error).toHaveBeenCalledWith(
				expect.objectContaining({ endpoint: "http://127.0.0.1:8180", ...difference }),
				expect.stringMatching(/not the one this verifier pushed/),
			);
			pushing.resolve(PUSHED);
			await checking;
			expect(check.altered).toBe(false);
			expect(log.warn).toHaveBeenCalledWith(
				expect.objectContaining({ endpoint: "http://127.0.0.1:8180" }),
				expect.stringMatching(/pushed .* again/),
			);
		},
	);

	it.each([
		["an id without a mark beside this load's", new Map([...PUSHED, ["evil", "permit(p, a, r);"]])],
		["another load's set", new Map([[`10-permit${OTHER_MARK}`, "permit(p, a, r);"]])],
		[
			"this load's and another load's",
			new Map([...PUSHED, [`30-extra${OTHER_MARK}`, "permit(p, a, r);"]]),
		],
	])("refuses while the agent holds %s, and never pushes over it", async (_label, held) => {
		const { check, push, tick } = readBack(() => held);
		tick();
		await check.poll();
		expect(check.altered).toBe(true);
		expect(push).not.toHaveBeenCalled();
	});

	it("answers again once the agent holds this load's set again, restored by someone else", async () => {
		let held: AgentPolicySet = new Map([...PUSHED, ["evil", "permit(p, a, r);"]]);
		const { check, log, tick } = readBack(() => held);
		tick();
		await check.poll();
		expect(check.altered).toBe(true);
		held = new Map(PUSHED);
		tick();
		await check.poll();
		expect(check.altered).toBe(false);
		expect(log.info).toHaveBeenCalledWith(
			expect.objectContaining({ endpoint: "http://127.0.0.1:8180" }),
			expect.stringMatching(/holds this verifier's policy set again/),
		);
	});

	it("says a changed set once, not at every check it stays changed", async () => {
		const { check, log, tick } = readBack(() => new Map([...PUSHED, ["evil", "p"]]));
		tick();
		await check.poll();
		tick();
		await check.poll();
		expect(errorLines(log)).toHaveLength(1);
	});

	it("compares with what the agent answered the last push — a push again is the new baseline", async () => {
		const reprinted: AgentPolicySet = new Map([[`10-permit${MARK}`, "re-printed"]]);
		let held: AgentPolicySet = new Map();
		const { check, push, tick } = readBack(
			() => held,
			async () => reprinted,
		);
		tick();
		await check.poll();
		expect(check.altered).toBe(false);
		held = reprinted;
		tick();
		await check.poll();
		expect(check.altered).toBe(false);
		// Compared with the agent's copy of the push again, not the first: no difference, no push.
		expect(push).toHaveBeenCalledTimes(1);
	});
});

describe("createAgentReadBack — when a check cannot finish", () => {
	it("keeps what it knew when the set cannot be read, says so, and reads again an interval on", async () => {
		let failing = true;
		const { check, read, log, tick } = readBack(() => {
			if (failing) throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
			return PUSHED;
		});
		tick();
		await check.poll();
		expect(check.altered).toBe(false);
		expect(log.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: expect.stringMatching(/ECONNREFUSED/) }),
			expect.stringMatching(/could not read .* back/),
		);
		failing = false;
		tick();
		await check.poll();
		expect(read).toHaveBeenCalledTimes(2);
	});

	it("keeps refusing when a set it could not read follows one it saw changed", async () => {
		let held: () => AgentPolicySet = () => new Map([...PUSHED, ["evil", "p"]]);
		const { check, tick } = readBack(() => held());
		tick();
		await check.poll();
		held = () => {
			throw new Error("503");
		};
		tick();
		await check.poll();
		expect(check.altered).toBe(true);
	});

	it("keeps refusing, and says so, when pushing this load's set again fails", async () => {
		const { check, log, tick } = readBack(
			() => new Map(),
			async () => {
				throw new Error("the agent refused the policy set");
			},
		);
		tick();
		await check.poll();
		expect(check.altered).toBe(true);
		expect(errorLines(log)).toEqual([
			expect.stringMatching(/not the one this verifier pushed/),
			expect.stringMatching(/could not push .* again/),
		]);
	});

	it("never rejects — a check runs behind an answer, where nothing would catch it", async () => {
		const { check, log, tick } = readBack(() => new Map());
		(log.error as ReturnType<typeof vi.fn>).mockImplementation(() => {
			throw new Error("the log is gone");
		});
		tick();
		await expect(check.poll()).resolves.toBeUndefined();
	});
});
