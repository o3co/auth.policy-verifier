// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The http engine's read-back of cedar-agent's policy set (#286).
 *
 * Every answer is read against what this load pushed (#283): a policy id it
 * names that is not one of this load's marks it foreign. Two things no answer
 * shows. A token holder can rewrite or delete one of this load's policies
 * under its own id, and the answers still name this load's ids. An agent that
 * lost its set — restarted, recreated — answers "no determining policy" to
 * everything, which is a deny that names nothing foreign.
 *
 * The agent's own copy of the set shows both. `PUT /v1/policies` answers with
 * it — each id, and the policy re-printed by the agent's Cedar — and a later
 * `GET /v1/policies` answers the same bytes while nothing changed it (checked
 * at every boot, and against cedar-agent 0.2.2). So the copy the push was
 * answered with is the baseline, and the agent's set is read back and
 * compared with it by id: a policy rewritten, deleted or added, or an empty
 * agent, is a difference.
 *
 * A check runs behind an answer, never before it: when an answer is asked for
 * and an interval has passed since the last check, one starts, and the answer
 * goes ahead on what is known. So this is detection with a window — up to an
 * interval, and the check's own time — not proof per answer; the engine still
 * does not confirm a revision. A verifier that answers nothing checks nothing,
 * and has nothing to protect.
 *
 * Every answer is refused while the agent was last seen holding a set other
 * than this load's — or answering its set in a way that cannot be compared:
 * an error, a set past the answer bound, something that is not a set, an
 * answer broken off or not whole within the deadline. That the read-back
 * cannot be made to fail quietly is what makes it worth anything: a token
 * holder who pads the set past the bound, or anything in the path that cuts
 * large answers off, would otherwise turn it off. The one read that leaves
 * things as they were is an agent that cannot be reached at all, and only
 * while its authorization calls fail too — its answers then fail on their
 * own, and "altered" would misname the fault. An agent that answers those
 * calls but not a read of its set is refusing to show it. While refusing, the
 * set is read again after a second, then two, doubling up to the interval, so
 * answers resume soon after the set is this load's again.
 *
 * An answer to a call that was out while a refusal began is refused too, even
 * when the set has been restored by the time it arrives: it may have come
 * from the set that was found changed.
 *
 * The set is pushed again only when it is plainly a damaged copy of this
 * load's: nothing in it but this load's own policies, some rewritten or gone —
 * or nothing at all, an agent restarted. A set holding anything this load did
 * not push — another load's, from a replica sharing the agent; a policy a
 * token holder added, marked or not — is not written over: two loads would
 * take turns overwriting each other, and what was added is for an operator to
 * see. It stays refused until the agent holds this load's set again, however
 * it gets there.
 */

import type { Logger } from "@o3co/auth.policy-verifier.core";

/** An agent's policy set, by id: each policy as the agent's Cedar re-printed it. */
export type AgentPolicySet = ReadonlyMap<string, string>;

/**
 * What reading the agent's set came to: the set it holds, or why what it
 * answered cannot be compared. Reading rejects only when no answer began to
 * arrive — the agent, or the connection to it, not there.
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
	/** How long after a check the next is due, while answers are not refused. */
	intervalMs: number;
	/** The clock the interval is measured on: monotonic. */
	now: () => number;
	/** Reads the agent's set; rejects only when no answer began to arrive. */
	read: () => Promise<AgentSetRead>;
	/** Pushes this load's set again; resolves with the agent's copy of it. */
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
	const { intervalMs, now, read, push, logger, fields } = options;
	let baseline = options.pushed;
	let refusal: ReadBackRefusal | undefined;
	let generation = 0;
	/** The refusal the last generation began with. */
	let begun: ReadBackRefusal | undefined;
	let answeredSinceCheck = false;
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
		logger[level](fields, message);
	}

	async function check(): Promise<void> {
		const answered = answeredSinceCheck;
		answeredSinceCheck = false;
		let answer: AgentSetRead;
		try {
			answer = await read();
		} catch (cause) {
			if (answered) {
				// Its authorization calls are answered; a read of its set is not.
				refuse(
					"unverifiable policy set",
					{ reason: describe(cause) },
					"cedar agent answers authorization calls but its policy set could not be read back — denying until it can",
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
		// A damaged copy of this load's set, or none: nothing in it this load did not push.
		const restorable = [...held.keys()].every((id) => baseline.has(id));
		refuse(
			"altered policy set",
			{ ...difference(baseline, held), restorable },
			restorable
				? "cedar agent's policy set is not the one this verifier pushed — denying, and pushing it again"
				: "cedar agent's policy set is not the one this verifier pushed, and holds policies it did not push — denying until it holds this verifier's again",
		);
		if (!restorable) return;
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
			answeredSinceCheck = true;
		},
		poll() {
			if (running !== undefined) return running;
			const due = refusal === undefined ? intervalMs : Math.min(intervalMs, recheckMs);
			if (now() - lastCheck < due) return undefined;
			lastCheck = now();
			const before = { refusal, generation };
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
					// Still refused for the same reason: back off, up to the interval, so
					// a set that stays refused is not read — and parsed — every second.
					recheckMs =
						refusal !== undefined && refusal === before.refusal && generation === before.generation
							? Math.min(recheckMs * 2, intervalMs)
							: RECHECK_WHILE_REFUSING_MS;
					running = undefined;
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
