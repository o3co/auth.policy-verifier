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
 * `GET /v1/policies` answers the same bytes while nothing changed it
 * (verified against cedar-agent 0.2.2). So the copy the push was answered with
 * is the baseline, and the agent's set is read back and compared with it by
 * id: a policy rewritten, deleted or added, or an empty agent, is a
 * difference.
 *
 * A check runs behind an answer, never before it: when an answer is asked for
 * and an interval has passed since the last check, one starts, and the answer
 * goes ahead on what is known. So this is detection with a window — up to an
 * interval, and the check's own time — not proof per answer; the engine still
 * does not confirm a revision. A verifier that answers nothing checks nothing,
 * and has nothing to protect.
 *
 * While the agent's set differs, every answer is refused. The set is pushed
 * again only when it is plainly this load's to restore: the agent holds
 * nothing, or holds only ids under this load's mark. A set holding anything
 * else — another load's ids, from a replica sharing the agent; an id without a
 * mark, which a token holder added — is not written over: two loads would
 * take turns overwriting each other, and what was added is for an operator to
 * see. It stays refused until the agent holds this load's set again, however
 * it gets there.
 */

import type { Logger } from "@o3co/auth.policy-verifier.core";

/** An agent's policy set, by id: each policy as the agent's Cedar re-printed it. */
export type AgentPolicySet = ReadonlyMap<string, string>;

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

export interface AgentReadBackOptions {
	/** The agent's copy of this load's set, as it answered the push. */
	pushed: AgentPolicySet;
	/** This load's mark, as it follows an id: `@` and 16 hex. */
	ownMark: string;
	/** How long after a check the next is due. */
	intervalMs: number;
	/** The clock the interval is measured on. */
	now: () => number;
	/** Reads the agent's set; rejects when it cannot. */
	read: () => Promise<AgentPolicySet>;
	/** Pushes this load's set again; resolves with the agent's copy of it. */
	push: () => Promise<AgentPolicySet>;
	/** For what an operator must see: a difference found, a push again, a check that failed. */
	logger: Logger;
	/** What every line carries: which engine, which agent. */
	fields: Readonly<Record<string, unknown>>;
}

export interface AgentReadBack {
	/**
	 * Whether the agent was last seen holding a set other than this load's —
	 * and every answer is refused until it is seen holding this load's again.
	 */
	readonly altered: boolean;
	/**
	 * Starts a check when one is due, in the background: never waits for it,
	 * and never rejects. Returns the check running — the one started, or one
	 * already out — or `undefined` when none is.
	 */
	poll(): Promise<void> | undefined;
}

export function createAgentReadBack(options: AgentReadBackOptions): AgentReadBack {
	const { ownMark, intervalMs, now, read, push, logger, fields } = options;
	let baseline = options.pushed;
	let altered = false;
	let lastCheck = now();
	let running: Promise<void> | undefined;

	async function check(): Promise<void> {
		let held: AgentPolicySet;
		try {
			held = await read();
		} catch (cause) {
			// Nothing learned: what was known stands, and the next check is an
			// interval on. An agent that cannot be read cannot answer either, and
			// its answers fail on their own.
			logger.warn(
				{ ...fields, reason: describe(cause) },
				"could not read the cedar agent's policy set back — checking again after the interval",
			);
			return;
		}
		if (sameSet(held, baseline)) {
			if (altered) {
				altered = false;
				logger.info(fields, "cedar agent holds this verifier's policy set again — answering");
			}
			return;
		}
		const restorable = held.size === 0 || [...held.keys()].every((id) => id.endsWith(ownMark));
		if (!altered) {
			altered = true;
			logger.error(
				{ ...fields, ...difference(baseline, held), restorable },
				restorable
					? "cedar agent's policy set is not the one this verifier pushed — denying, and pushing it again"
					: "cedar agent's policy set is not the one this verifier pushed, and holds policies of another's — denying until it holds this verifier's again",
			);
		}
		if (!restorable) return;
		try {
			baseline = await push();
		} catch (cause) {
			logger.error(
				{ ...fields, reason: describe(cause) },
				"could not push the policy set to the cedar agent again — denying until it holds it",
			);
			return;
		}
		altered = false;
		logger.warn(fields, "pushed the policy set to the cedar agent again — answering");
	}

	return {
		get altered() {
			return altered;
		},
		poll() {
			if (running !== undefined) return running;
			if (now() - lastCheck < intervalMs) return undefined;
			lastCheck = now();
			running = check()
				// Behind an answer nothing awaits it, so nothing may escape it — a
				// logger that throws included. What it knew stands.
				.catch(() => undefined)
				.finally(() => {
					running = undefined;
				});
			return running;
		},
	};
}

function sameSet(a: AgentPolicySet, b: AgentPolicySet): boolean {
	if (a.size !== b.size) return false;
	for (const [id, content] of a) if (b.get(id) !== content) return false;
	return true;
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
