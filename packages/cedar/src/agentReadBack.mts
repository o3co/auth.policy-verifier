// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The http engine's read-back of cedar-agent's policy set.
 *
 * An answer naming a policy id that is not one of this load's is marked
 * foreign, but two things no answer shows. A token holder can rewrite or
 * delete one of this load's policies under its own id, and the answers still
 * name this load's ids. An agent that lost its set — restarted, recreated —
 * answers "no determining policy" to everything, a deny that names nothing
 * foreign.
 *
 * The agent's own copy of the set shows both. `PUT /v1/policies` answers with
 * it — each id, and the policy re-printed by the agent's Cedar — and a later
 * `GET /v1/policies` answers the same bytes while nothing changed it (checked
 * at every boot, and against cedar-agent 0.2.2). That copy is the baseline;
 * the agent's set is read back and compared with it by id, so a policy
 * rewritten, deleted or added, or an empty agent, is a difference.
 *
 * A check runs behind an answer, never before it: when an answer is asked for
 * and the wait since the last check has passed, one starts, and the answer
 * goes ahead on what is known. Each wait is drawn anew from half the interval
 * to all of it. This is detection with a window — up to an interval, and the
 * check's own time — not proof per answer; the engine still does not confirm
 * a revision. A verifier that answers nothing checks nothing.
 *
 * Every answer is refused while the agent was last seen holding a set other
 * than this load's, or answering its set in a way that cannot be compared: an
 * error, a set past the answer bound, something that is not a set, an answer
 * broken off, late, or never begun. The read-back must not fail quietly: a
 * token holder who pads the set past the bound, or anything in the path that
 * cuts large answers off, would otherwise turn it off. The one read that
 * leaves things as they were is a connection that fails outright while the
 * agent answers no authorization call either: it is down, its answers fail
 * on their own, and "altered" would misname the fault. An agent that answers
 * those calls but whose set cannot be read is not showing it, and answers are
 * refused. While refusing, the set is read again after a second, then two,
 * doubling up to the interval, so answers resume soon after the set is this
 * load's again. An answer to a call that was out while a refusal began is
 * refused too, even when the set has been restored by the time it arrives: it
 * may have come from the set that was found changed.
 *
 * The set is pushed again only into an agent that holds nothing — restarted or
 * recreated: an accident, and a harmless one, since an empty set denies
 * everything. A set that holds anything else is not written over: a policy of
 * this load's rewritten or deleted, one added, marked or not, is what
 * tampering looks like, and is left for an operator to see; another load's
 * set, from a replica sharing the agent, would be overwritten back and forth.
 * It stays refused until the agent holds this load's set again, however it
 * gets there — a restart of the verifier pushes it.
 *
 * This does not stop someone holding the agent's token. They can lift a
 * refusal themselves — put the set back, or empty the agent so it is pushed
 * again — and change it again after the next check; a change made and undone
 * within half an interval of a check they saw goes unseen for certain. The
 * read-back detects, logs and refuses what it sees, and heals a restarted
 * agent; the token is the boundary, as it is for the load's marks.
 */

import type { Logger } from "@o3co/auth.policy-verifier.core";

/** An agent's policy set, by id: each policy as the agent's Cedar re-printed it. */
export type AgentPolicySet = ReadonlyMap<string, string>;

/**
 * What reading the agent's set came to: the set it holds, or why what it
 * answered cannot be compared. Reading rejects only when the connection
 * failed outright — refused, reset, not found — before any answer began; a
 * read that timed out is `unverifiable`.
 */
export type AgentSetRead = { readonly held: AgentPolicySet } | { readonly unverifiable: string };

/** Why answers are refused: the read-back's labels for a foreign answer (`ForeignAnswer`). */
export type ReadBackRefusal = "altered policy set" | "unverifiable policy set";

/** How soon the set is read again once answers begin to be refused; it doubles while they stay refused. */
const RECHECK_WHILE_REFUSING_MS = 1_000;

/**
 * The set in cedar-agent's answer to `PUT` or `GET /v1/policies` — a list of
 * `{ id, content }` — or `undefined` for anything else. The agent holds one
 * policy per id, so a list naming an id twice is not its set.
 */
export function agentPolicySetOf(body: unknown): AgentPolicySet | undefined {
	if (!Array.isArray(body)) return undefined;
	const set = new Map<string, string>();
	for (const item of body) {
		const { id, content } = (typeof item === "object" && item !== null ? item : {}) as {
			id?: unknown;
			content?: unknown;
		};
		if (typeof id !== "string" || typeof content !== "string" || set.has(id)) return undefined;
		set.set(id, content);
	}
	return set;
}

/** Whether two copies of a set are the same: the same ids, each the same text. */
export function sameAgentSet(a: AgentPolicySet, b: AgentPolicySet): boolean {
	if (a.size !== b.size) return false;
	for (const [id, content] of a) if (b.get(id) !== content) return false;
	return true;
}

export interface AgentReadBackOptions {
	/** The agent's copy of this load's set, as it answered the push. */
	pushed: AgentPolicySet;
	/** The most a check waits for the next, while answers are not refused; it waits from half this. */
	intervalMs: number;
	/** Draws each wait within the interval: a number in [0, 1). */
	random: () => number;
	/** The clock the interval is measured on: monotonic. */
	now: () => number;
	/** Reads the agent's set; rejects only when the connection failed outright. */
	read: () => Promise<AgentSetRead>;
	/** Pushes this load's set again, into an empty agent; resolves with the agent's copy of it. */
	push: () => Promise<AgentPolicySet>;
	/** For what an operator must see: a difference found, a push again, a check that failed. */
	logger: Logger;
	/** What every line carries: which engine, which agent. */
	fields: Readonly<Record<string, unknown>>;
}

export interface AgentReadBack {
	/**
	 * Why every answer is refused, or `undefined` while the agent was last seen
	 * holding this load's set as pushed.
	 */
	readonly refusal: ReadBackRefusal | undefined;
	/** Counts the refusals begun: taken before a call, for {@link refusedSince} after it. */
	readonly generation: number;
	/**
	 * Why the answer to a call made at `generation` is refused: the refusal now,
	 * or one that began while the call was out — lifted since, it still may
	 * have answered it.
	 */
	refusedSince(generation: number): ReadBackRefusal | undefined;
	/** The agent answered an authorization call: it is there, whatever a read of its set meets. */
	answered(): void;
	/**
	 * Starts a check when one is due, in the background: never waits for it,
	 * and never rejects. Returns the check running — the one started, or one
	 * already out — or `undefined` when none is.
	 */
	poll(): Promise<void> | undefined;
}

export function createAgentReadBack(options: AgentReadBackOptions): AgentReadBack {
	const { intervalMs, now, random, read, push, logger, fields } = options;
	/**
	 * From half the interval to all of it, drawn anew after every check. A
	 * draw that throws or is not a number is the whole interval: the checks go
	 * on whatever the source does.
	 */
	const drawWait = () => {
		let draw: number;
		try {
			draw = random();
		} catch {
			draw = 1;
		}
		return intervalMs * (0.5 + 0.5 * (Number.isFinite(draw) ? Math.min(Math.max(draw, 0), 1) : 1));
	};
	let wait = drawWait();
	let baseline = options.pushed;
	let refusal: ReadBackRefusal | undefined;
	let generation = 0;
	/** The refusal the last generation began with. */
	let begun: ReadBackRefusal | undefined;
	/** Authorization calls answered, and how many of them a check has accounted for. */
	let answeredCalls = 0;
	let countedCalls = 0;
	/** One line per streak, not per check: while refusing, checks come every second. */
	let unreachableStreak = false;
	let pushFailing = false;
	let recheckMs = RECHECK_WHILE_REFUSING_MS;
	let lastCheck = now();
	let running: Promise<void> | undefined;

	/** Refuses as `why` from now on; a new refusal is a new generation, said once. */
	function refuse(why: ReadBackRefusal, detail: Record<string, unknown>, message: string): void {
		if (refusal === why) return;
		refusal = why;
		begun = why;
		generation++;
		pushFailing = false;
		logger.error({ ...fields, ...detail }, message);
	}

	function lift(message: string, level: "info" | "warn"): void {
		refusal = undefined;
		pushFailing = false;
		// No call is made while refusing: every call answered since the refusal
		// began was made before it, and its answer was refused as late. None is
		// the next check's to weigh — not even those a read then left counted.
		countedCalls = answeredCalls;
		logger[level](fields, message);
	}

	async function check(): Promise<void> {
		const answeredBefore = answeredCalls;
		let answer: AgentSetRead;
		try {
			answer = await read();
		} catch (cause) {
			// Calls answered since the last check, during this read included.
			const answered = answeredCalls > countedCalls;
			countedCalls = answeredCalls;
			// Already refusing: a read that cannot reach the agent says nothing
			// new, and a call that was out before the refusal is no news either.
			if (refusal !== undefined) return;
			if (answered) {
				refuse(
					"unverifiable policy set",
					{ reason: describe(cause) },
					"cedar agent answered authorization calls since the last check but its policy set could not be read back — blocked, or gone down since — denying until it can be",
				);
				return;
			}
			// Not reached at all, and not answering calls either: nothing learned.
			// Its answers fail on their own, saying so; "altered" would misname it.
			if (!unreachableStreak) {
				unreachableStreak = true;
				logger.warn(
					{ ...fields, reason: describe(cause) },
					"could not reach the cedar agent to read its policy set back — checking again",
				);
			}
			return;
		}
		// The read answered for the calls before it began; those answered while
		// it was out are for the next check to account for.
		countedCalls = answeredBefore;
		unreachableStreak = false;
		if ("unverifiable" in answer) {
			refuse(
				"unverifiable policy set",
				{ reason: answer.unverifiable },
				"cedar agent did not answer its policy set in a way that can be compared with the one this verifier pushed — denying until it does",
			);
			return;
		}
		const { held } = answer;
		if (sameAgentSet(held, baseline)) {
			if (refusal !== undefined) {
				lift("cedar agent holds this verifier's policy set again — answering", "info");
			}
			return;
		}
		// An agent that holds nothing restarted; anything else was changed.
		const restorable = held.size === 0;
		refuse(
			"altered policy set",
			{ ...difference(baseline, held), restorable },
			restorable
				? "cedar agent holds no policy set — restarted or recreated — denying, and pushing this verifier's again"
				: "cedar agent's policy set is not the one this verifier pushed — denying until it holds this verifier's again",
		);
		if (!restorable) return;
		// Read, then push: two calls, and cedar-agent has no conditional PUT. A
		// verifier that pushes into the empty agent between them is overwritten —
		// the README says so, and why one agent per verifier.
		try {
			baseline = await push();
		} catch (cause) {
			if (!pushFailing) {
				pushFailing = true;
				logger.error(
					{ ...fields, reason: describe(cause) },
					"could not push the policy set to the cedar agent again — denying until it holds it",
				);
			}
			return;
		}
		lift("pushed the policy set to the cedar agent again — answering", "warn");
	}

	return {
		get refusal() {
			return refusal;
		},
		get generation() {
			return generation;
		},
		refusedSince(since) {
			return refusal ?? (generation !== since ? begun : undefined);
		},
		answered() {
			answeredCalls++;
		},
		poll() {
			if (running !== undefined) return running;
			const due = refusal === undefined ? wait : Math.min(intervalMs, recheckMs);
			if (now() - lastCheck < due) return undefined;
			lastCheck = now();
			const refusing = refusal !== undefined;
			running = check()
				// Behind an answer nothing awaits it, so nothing may escape it. What
				// it knew stands; the fault is said if the log still can say it.
				.catch((cause: unknown) => {
					try {
						logger.error(
							{ ...fields, reason: describe(cause) },
							"cedar agent policy set read-back failed unexpectedly",
						);
					} catch {
						// The log is what failed; there is nowhere left to say it.
					}
				})
				.finally(() => {
					running = undefined;
					// Still refusing: back off, up to the interval, so a set that stays
					// refused is not read — and parsed — every second. A refusal that
					// changes kind is still one refusal; one begun anew starts at a second.
					recheckMs =
						refusing && refusal !== undefined
							? Math.min(recheckMs * 2, intervalMs)
							: RECHECK_WHILE_REFUSING_MS;
					wait = drawWait();
				});
			return running;
		},
	};
}

/** How the held set differs from the baseline, in counts: ids and policy text are not the log's. */
function difference(baseline: AgentPolicySet, held: AgentPolicySet) {
	let changed = 0;
	let missing = 0;
	for (const [id, content] of baseline) {
		const now = held.get(id);
		if (now === undefined) missing++;
		else if (now !== content) changed++;
	}
	const added = [...held.keys()].filter((id) => !baseline.has(id)).length;
	return { changed, missing, added };
}

function describe(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
