// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The read-back of cedar-agent's policy set, on its own: what a check reads,
 * what it makes of the set the agent holds, when it pushes this load's set
 * again, and when it runs at all. The engine's wiring of it is pinned in
 * `httpEngine.test.mts`. The agent's own behaviour — its PUT answer and a
 * later GET byte-identical, a token holder's edits showing in the GET, a
 * restart coming back empty — is what a real cedar-agent 0.2.2 does, and the
 * first is checked again at every boot.
 */

import type { Logger } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it, vi } from "vitest";
import {
	type AgentPolicySet,
	type AgentSetRead,
	agentPolicySetOf,
	createAgentReadBack,
	sameAgentSet,
} from "../agentReadBack.mjs";

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

/** A promise and the functions that settle it — to hold a read or a push open. */
function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (reason: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

/** What a read of `held` comes to: the set, as the agent answered it. */
const holding = (held: AgentPolicySet): AgentSetRead => ({ held });

function readBack(
	answer: () => AgentSetRead | Promise<AgentSetRead>,
	push: () => Promise<AgentPolicySet> = async () => PUSHED,
	// The whole interval, unless a test draws otherwise.
	random: () => number = () => 1,
) {
	let clock = 1_000_000;
	const log = logger();
	const read = vi.fn(async () => answer());
	const pushed = vi.fn(push);
	const check = createAgentReadBack({
		pushed: PUSHED,
		intervalMs: 30_000,
		now: () => clock,
		random,
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

const messages = (method: unknown) =>
	(method as ReturnType<typeof vi.fn>).mock.calls.map(([, message]) => message);

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

	it("compares two copies by id and text, whatever order they came in", () => {
		expect(sameAgentSet(PUSHED, new Map([...PUSHED].reverse()))).toBe(true);
		expect(sameAgentSet(PUSHED, new Map([...PUSHED].slice(1)))).toBe(false);
		expect(sameAgentSet(PUSHED, new Map([...PUSHED, [`10-permit${MARK}`, "x"]]))).toBe(false);
	});
});

describe("createAgentReadBack — when it reads the agent's set back", () => {
	it("reads nothing within an interval of the push, and once when one has passed", async () => {
		const { check, read, tick } = readBack(() => holding(PUSHED));
		expect(check.poll()).toBeUndefined();
		tick(29_999);
		expect(check.poll()).toBeUndefined();
		tick(1);
		await check.poll();
		expect(read).toHaveBeenCalledTimes(1);
		// The interval runs from the check just made.
		expect(check.poll()).toBeUndefined();
	});

	it("draws each wait anew, from half the interval to all of it — when the next check falls cannot be read off the last", async () => {
		const draws = [0, 0.5, 0.999];
		const { check, read, tick } = readBack(
			() => holding(PUSHED),
			undefined,
			() => draws.shift() ?? 1,
		);
		// Drawn at boot: 0 — half the interval.
		for (const wait of [15_000, 22_500, 29_985]) {
			const reads = read.mock.calls.length;
			tick(wait - 1);
			expect(check.poll()).toBeUndefined();
			tick(1);
			await check.poll();
			expect(read).toHaveBeenCalledTimes(reads + 1);
		}
	});

	it.each([
		[
			"throws",
			() => {
				throw new Error("no entropy");
			},
		],
		["answers NaN", () => Number.NaN],
	])("waits the whole interval when the draw %s — the checks go on", async (_label, random) => {
		const { check, read, tick } = readBack(() => holding(PUSHED), undefined, random);
		tick(29_999);
		expect(check.poll()).toBeUndefined();
		tick(1);
		await check.poll();
		tick(30_000);
		await check.poll();
		expect(read).toHaveBeenCalledTimes(2);
	});

	it("runs one check at a time, however many answers ask while it is out", async () => {
		const reading = deferred<AgentSetRead>();
		const { check, read, tick } = readBack(() => reading.promise);
		tick();
		const first = check.poll();
		tick();
		expect(check.poll()).toBe(first);
		reading.resolve(holding(PUSHED));
		await first;
		expect(read).toHaveBeenCalledTimes(1);
	});

	it("reads again a second after it begins to refuse, then backs off, doubling up to the interval", async () => {
		const { check, read, tick } = readBack(() => ({ unverifiable: "answered 503" }));
		tick();
		await check.poll();
		expect(check.refusal).toBe("unverifiable policy set");
		for (const wait of [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]) {
			const reads = read.mock.calls.length;
			tick(wait - 1);
			expect(check.poll()).toBeUndefined();
			tick(1);
			await check.poll();
			expect(read).toHaveBeenCalledTimes(reads + 1);
		}
	});

	it("keeps backing off when a refusal changes kind — it is one refusal still", async () => {
		let answer: AgentSetRead = { unverifiable: "answered 503" };
		const { check, read, tick } = readBack(() => answer);
		tick();
		await check.poll();
		tick(1_000);
		await check.poll();
		// Backed off to 2 s; now the agent shows a set, changed.
		answer = holding(new Map([...PUSHED, ["evil", "p"]]));
		tick(2_000);
		await check.poll();
		expect(check.refusal).toBe("altered policy set");
		const reads = read.mock.calls.length;
		tick(3_999);
		expect(check.poll()).toBeUndefined();
		tick(1);
		await check.poll();
		expect(read).toHaveBeenCalledTimes(reads + 1);
	});
});

describe("createAgentReadBack — what it makes of the set the agent holds", () => {
	it("answers on while the agent holds this load's set as pushed", async () => {
		const { check, push, tick } = readBack(() => holding(new Map(PUSHED)));
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
		expect(push).not.toHaveBeenCalled();
	});

	it("refuses while the agent holds nothing — restarted — and pushes this load's set into it", async () => {
		const pushing = deferred<AgentPolicySet>();
		const { check, push, log, tick } = readBack(
			() => holding(new Map()),
			() => pushing.promise,
		);
		tick();
		const checking = check.poll();
		await vi.waitFor(() => expect(push).toHaveBeenCalledTimes(1));
		// Refused from the moment the difference is seen until the push lands.
		expect(check.refusal).toBe("altered policy set");
		expect(log.error).toHaveBeenCalledWith(
			expect.objectContaining({
				endpoint: "http://127.0.0.1:8180",
				changed: 0,
				missing: 2,
				added: 0,
				restorable: true,
			}),
			expect.stringMatching(/holds no policy set — restarted or recreated — denying, and pushing/),
		);
		pushing.resolve(PUSHED);
		await checking;
		expect(check.refusal).toBeUndefined();
		expect(messages(log.warn)).toEqual([expect.stringMatching(/pushed .* again — answering/)]);
	});

	it.each([
		// Rewritten, deleted, added: what tampering looks like, left for an operator to see.
		[
			"one of its policies rewritten under its own id",
			new Map([...PUSHED, [`10-permit${MARK}`, "permit(principal, action, resource);"]]),
		],
		[
			"one of its policies deleted",
			new Map([[`10-permit${MARK}`, PUSHED.get(`10-permit${MARK}`) as string]]),
		],
		// Marked or not, the mark being public: what was added is for an operator to see.
		[
			"a policy added under this load's mark",
			new Map([...PUSHED, [`evil${MARK}`, "permit(p, a, r);"]]),
		],
		["a policy added without a mark", new Map([...PUSHED, ["evil", "permit(p, a, r);"]])],
		["another load's set", new Map([[`10-permit${OTHER_MARK}`, "permit(p, a, r);"]])],
		[
			"this load's and another load's",
			new Map([...PUSHED, [`30-extra${OTHER_MARK}`, "permit(p, a, r);"]]),
		],
	])("refuses while the agent holds %s, and never pushes over it", async (_label, held) => {
		const { check, push, log, tick } = readBack(() => holding(held));
		tick();
		await check.poll();
		expect(check.refusal).toBe("altered policy set");
		expect(push).not.toHaveBeenCalled();
		expect(log.error).toHaveBeenCalledWith(
			expect.objectContaining({ restorable: false }),
			expect.stringMatching(
				/not the one this verifier pushed — denying until it holds this verifier's again/,
			),
		);
	});

	it("answers again once the agent holds this load's set again, restored by someone else", async () => {
		let held: AgentPolicySet = new Map([...PUSHED, ["evil", "permit(p, a, r);"]]);
		const { check, log, tick } = readBack(() => holding(held));
		tick();
		await check.poll();
		expect(check.refusal).toBe("altered policy set");
		held = new Map(PUSHED);
		tick(1_000);
		await check.poll();
		expect(check.refusal).toBeUndefined();
		expect(log.info).toHaveBeenCalledWith(
			expect.objectContaining({ endpoint: "http://127.0.0.1:8180" }),
			expect.stringMatching(/holds this verifier's policy set again/),
		);
	});

	it("says a changed set once, not at every check it stays changed", async () => {
		const { check, log, tick } = readBack(() => holding(new Map([...PUSHED, ["evil", "p"]])));
		tick();
		await check.poll();
		tick();
		await check.poll();
		expect(messages(log.error)).toHaveLength(1);
	});

	it("compares with what the agent answered the last push — a push again is the new baseline", async () => {
		const reprinted: AgentPolicySet = new Map([[`10-permit${MARK}`, "re-printed"]]);
		let held: AgentPolicySet = new Map();
		const { check, push, tick } = readBack(
			() => holding(held),
			async () => reprinted,
		);
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
		held = reprinted;
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
		// Compared with the agent's copy of the push again, not the first: no difference, no push.
		expect(push).toHaveBeenCalledTimes(1);
	});
});

describe("createAgentReadBack — an agent that will not show its set", () => {
	it.each([
		"answered 503: no description",
		"a policy set of more than 1 MiB",
		"something that is not a policy set",
		"no answer within 10000 ms",
	])(
		"refuses when the agent answers with %s — it cannot be turned off by growing the set",
		async (why) => {
			const { check, push, log, tick } = readBack(() => ({ unverifiable: why }));
			tick();
			await check.poll();
			expect(check.refusal).toBe("unverifiable policy set");
			// It cannot see what the agent holds, so it pushes nothing over it.
			expect(push).not.toHaveBeenCalled();
			expect(log.error).toHaveBeenCalledWith(
				expect.objectContaining({ reason: why }),
				expect.stringMatching(/did not answer its policy set in a way that can be compared/),
			);
		},
	);

	it("answers again once the set can be read and is this load's", async () => {
		let answer: AgentSetRead = { unverifiable: "a policy set of more than 1 MiB" };
		const { check, tick } = readBack(() => answer);
		tick();
		await check.poll();
		answer = holding(PUSHED);
		tick(1_000);
		await check.poll();
		expect(check.refusal).toBeUndefined();
	});

	it("goes from a set it cannot read to one it sees changed, and pushes it again", async () => {
		let answer: AgentSetRead = { unverifiable: "answered 500: boom" };
		const { check, push, tick } = readBack(() => answer);
		tick();
		await check.poll();
		answer = holding(new Map());
		tick(1_000);
		await check.poll();
		expect(push).toHaveBeenCalledTimes(1);
		expect(check.refusal).toBeUndefined();
	});
});

describe("createAgentReadBack — calls that were out across a refusal", () => {
	it("counts each refusal begun, and refuses a call made before one began — though it was lifted since", async () => {
		// An agent that came back empty: pushed again, and lifted, in one check.
		const { check, tick } = readBack(() => holding(new Map()));
		const before = check.generation;
		expect(check.refusedSince(before)).toBeUndefined();
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
		expect(check.generation).toBe(before + 1);
		expect(check.refusedSince(before)).toBe("altered policy set");
		// A call made after it is not.
		expect(check.refusedSince(check.generation)).toBeUndefined();
	});

	it("refuses a call made while refusing, as that refusal", async () => {
		const { check, tick } = readBack(() => ({ unverifiable: "answered 503" }));
		tick();
		await check.poll();
		expect(check.refusedSince(check.generation)).toBe("unverifiable policy set");
	});
});

describe("createAgentReadBack — an agent that answers calls but will not be read", () => {
	it("refuses when a read cannot reach an agent that answered a call since the last check", async () => {
		const { check, log, tick } = readBack(() => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		});
		check.answered();
		tick();
		await check.poll();
		expect(check.refusal).toBe("unverifiable policy set");
		expect(log.error).toHaveBeenCalledWith(
			expect.objectContaining({ reason: expect.stringMatching(/ECONNREFUSED/) }),
			expect.stringMatching(
				/answered authorization calls since the last check but its policy set could not be read back/,
			),
		);
	});

	it("counts a call answered while the read was out — the read that failed is still a read of an agent that answers", async () => {
		const reading = deferred<AgentSetRead>();
		const { check, tick } = readBack(() => reading.promise);
		tick();
		const checking = check.poll();
		check.answered();
		reading.reject(new Error("read ECONNRESET"));
		await checking;
		expect(check.refusal).toBe("unverifiable policy set");
	});

	it("counts each answered call for one check only: refused, restored, then a read that cannot reach it with no call answered changes nothing", async () => {
		let answer: () => AgentSetRead = () => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		};
		const { check, tick } = readBack(() => answer());
		check.answered();
		tick();
		await check.poll();
		expect(check.refusal).toBe("unverifiable policy set");
		answer = () => holding(PUSHED);
		tick(1_000);
		await check.poll();
		expect(check.refusal).toBeUndefined();
		answer = () => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		};
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
	});

	it("does not change the kind of a refusal on a read that cannot reach the agent — a call out before it answered after", async () => {
		let answer: () => AgentSetRead = () => holding(new Map([...PUSHED, ["evil", "p"]]));
		const { check, tick } = readBack(() => answer());
		tick();
		await check.poll();
		const generation = check.generation;
		check.answered();
		answer = () => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		};
		tick(1_000);
		await check.poll();
		expect(check.refusal).toBe("altered policy set");
		expect(check.generation).toBe(generation);
	});

	it("accounts a call answered before a read that succeeded to that read — a later read that cannot connect, with no call since, is an agent down", async () => {
		let answer: () => AgentSetRead = () => holding(PUSHED);
		const { check, log, tick } = readBack(() => answer());
		check.answered();
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
		answer = () => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		};
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
		expect(messages(log.warn)).toEqual([expect.stringMatching(/could not reach the cedar agent/)]);
	});

	it("keeps a call answered while a read that succeeded was out for the next check — a later read that cannot connect is refused", async () => {
		const reading = deferred<AgentSetRead>();
		let answer: () => AgentSetRead | Promise<AgentSetRead> = () => reading.promise;
		const { check, tick } = readBack(() => answer());
		tick();
		const checking = check.poll();
		// Answered while the read is out; the read then shows the set as pushed.
		check.answered();
		reading.resolve(holding(PUSHED));
		await checking;
		expect(check.refusal).toBeUndefined();
		answer = () => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		};
		tick();
		await check.poll();
		expect(check.refusal).toBe("unverifiable policy set");
	});

	it("forgets a call answered while it pushed into an empty agent — no news of the set it answers from after", async () => {
		const pushing = deferred<AgentPolicySet>();
		let answer: () => AgentSetRead = () => holding(new Map());
		const { check, push, tick } = readBack(
			() => answer(),
			() => pushing.promise,
		);
		tick();
		const checking = check.poll();
		await vi.waitFor(() => expect(push).toHaveBeenCalledTimes(1));
		// A call out before the refusal, answered while the push is out.
		check.answered();
		pushing.resolve(PUSHED);
		await checking;
		expect(check.refusal).toBeUndefined();
		answer = () => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		};
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
	});

	it("keeps what it knew when neither a call nor a read reaches the agent — each answered call counts once", async () => {
		const { check, tick } = readBack(() => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		});
		check.answered();
		tick();
		await check.poll();
		expect(check.refusal).toBe("unverifiable policy set");
		// It is refusing, so no call goes out, and none is answered: a read that
		// cannot reach it now learns nothing, and the refusal it had stands.
		tick(1_000);
		await check.poll();
		expect(check.refusal).toBe("unverifiable policy set");
	});
});

describe("createAgentReadBack — when a check cannot finish", () => {
	it("says what a read failed with, whatever was thrown", async () => {
		const { check, log, tick } = readBack(() => {
			throw "a plain string";
		});
		tick();
		await check.poll();
		expect(log.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "a plain string" }),
			expect.stringMatching(/could not reach/),
		);
	});

	it("says an agent it cannot reach once per streak, not at every check", async () => {
		let reachable = false;
		const { check, log, tick } = readBack(() => {
			if (!reachable) throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
			return holding(PUSHED);
		});
		for (let i = 0; i < 3; i++) {
			tick();
			await check.poll();
		}
		expect(messages(log.warn)).toHaveLength(1);
		reachable = true;
		tick();
		await check.poll();
		reachable = false;
		tick();
		await check.poll();
		expect(messages(log.warn)).toHaveLength(2);
	});

	it("says a push again that keeps failing once, and backs off from it", async () => {
		const { check, log, push, tick } = readBack(
			() => holding(new Map()),
			async () => {
				throw new Error("the agent refused the policy set");
			},
		);
		for (const wait of [30_000, 1_000, 2_000, 4_000]) {
			tick(wait);
			await check.poll();
		}
		expect(push).toHaveBeenCalledTimes(4);
		expect(messages(log.error).filter((line) => /could not push/.test(line))).toHaveLength(1);
	});

	it("keeps what it knew when the agent cannot be reached, says so, and reads again an interval on", async () => {
		let reachable = false;
		const { check, read, log, tick } = readBack(() => {
			if (!reachable) throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
			return holding(PUSHED);
		});
		tick();
		await check.poll();
		expect(check.refusal).toBeUndefined();
		expect(log.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: expect.stringMatching(/ECONNREFUSED/) }),
			expect.stringMatching(/could not reach the cedar agent to read its policy set back/),
		);
		reachable = true;
		tick();
		await check.poll();
		expect(read).toHaveBeenCalledTimes(2);
	});

	it("keeps refusing when an agent it saw changed cannot then be reached", async () => {
		let answer: () => AgentSetRead = () => holding(new Map([...PUSHED, ["evil", "p"]]));
		const { check, tick } = readBack(() => answer());
		tick();
		await check.poll();
		answer = () => {
			throw new Error("connect ECONNREFUSED 127.0.0.1:8180");
		};
		tick(1_000);
		await check.poll();
		expect(check.refusal).toBe("altered policy set");
	});

	it("keeps refusing, and says so, when pushing this load's set again fails", async () => {
		const { check, log, tick } = readBack(
			() => holding(new Map()),
			async () => {
				throw new Error("the agent refused the policy set");
			},
		);
		tick();
		await check.poll();
		expect(check.refusal).toBe("altered policy set");
		expect(messages(log.error)).toEqual([
			expect.stringMatching(/holds no policy set/),
			expect.stringMatching(/could not push .* again/),
		]);
	});

	it("never rejects, and says what went wrong while the log can — a check runs behind an answer, where nothing would catch it", async () => {
		// A read that answers nothing this knows: a fault here, not the agent's.
		const { check, log, tick } = readBack(() => undefined as unknown as AgentSetRead);
		tick();
		await expect(check.poll()).resolves.toBeUndefined();
		expect(messages(log.error)).toEqual([expect.stringMatching(/failed unexpectedly/)]);

		(log.error as ReturnType<typeof vi.fn>).mockImplementation(() => {
			throw new Error("the log is gone");
		});
		tick();
		await expect(check.poll()).resolves.toBeUndefined();
	});
});
