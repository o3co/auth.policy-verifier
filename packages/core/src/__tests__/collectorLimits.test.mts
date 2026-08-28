// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { AttributePipeline } from "../AttributePipeline.mjs";
import {
	DEFAULT_COLLECT_DEADLINE_MS,
	DEFAULT_COLLECTOR_CONCURRENCY,
	DEFAULT_COLLECTOR_TIMEOUT_MS,
} from "../collectorLimits.mjs";
import { CollectorTimeoutError } from "../errors.mjs";
import { RulePipeline } from "../RulePipeline.mjs";
import type {
	AttributeCollector,
	Attributes,
	CollectorRequest,
	Rule,
	RuleCollector,
} from "../types.mjs";

const request: CollectorRequest = {
	subject: {},
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A collector that never settles and never looks at its signal — the shape the
 * whole issue is about. A collector that cooperates cannot prove the pipeline
 * bounds anything, because it is the collector doing the bounding.
 */
const hanging = (): AttributeCollector => ({
	collect: () => new Promise<Attributes>(() => {}),
});

/** A collector that rejects as soon as its signal aborts, recording that it did. */
function cancellable(): { collector: AttributeCollector; aborted: () => boolean } {
	let aborted = false;
	return {
		aborted: () => aborted,
		collector: {
			collect: (context) =>
				new Promise<Attributes>((_, reject) => {
					context.signal.addEventListener(
						"abort",
						() => {
							aborted = true;
							reject(context.signal.reason);
						},
						{ once: true },
					);
				}),
		},
	};
}

describe("AttributePipeline — collector cancellation (#115)", () => {
	it("hands every collector an AbortSignal to pass to its own I/O", async () => {
		const seen: AbortSignal[] = [];
		const record = (): AttributeCollector => ({
			collect: async (context) => {
				seen.push(context.signal);
				return new Map();
			},
		});

		await new AttributePipeline([record(), record()]).collect(request);

		expect(seen).toHaveLength(2);
		for (const signal of seen) {
			expect(signal).toBeInstanceOf(AbortSignal);
			// Not aborted: a collector that finished was not cancelled, and a
			// signal that aborts on success would make `signal.aborted` useless
			// for telling "the request is over" from "you were cut off".
			expect(signal.aborted).toBe(false);
		}
	});

	it("gives each collector its own signal, so one timing out does not cancel the rest", async () => {
		const seen = new Set<AbortSignal>();
		const record = (): AttributeCollector => ({
			collect: async (context) => {
				seen.add(context.signal);
				return new Map();
			},
		});

		await new AttributePipeline([record(), record(), record()]).collect(request);

		expect(seen.size).toBe(3);
	});

	it("propagates a signal the caller already aborted without running any collector", async () => {
		let started = false;
		const collector: AttributeCollector = {
			collect: async () => {
				started = true;
				return new Map();
			},
		};
		const controller = new AbortController();
		controller.abort(new Error("client went away"));

		await expect(
			new AttributePipeline([collector]).collect({ ...request, signal: controller.signal }),
		).rejects.toThrow("client went away");
		expect(started).toBe(false);
	});

	it("cancels in-flight collectors when the caller aborts mid-collect", async () => {
		const { collector, aborted } = cancellable();
		const controller = new AbortController();
		const collecting = new AttributePipeline([collector]).collect({
			...request,
			signal: controller.signal,
		});

		await sleep(5);
		controller.abort(new Error("client went away"));

		await expect(collecting).rejects.toThrow("client went away");
		expect(aborted()).toBe(true);
	});
});

describe("AttributePipeline — per-collector timeout (#115)", () => {
	it("refuses a collector that overruns its own budget", async () => {
		const pipeline = new AttributePipeline([hanging()], {
			collectorTimeoutMs: 20,
			deadlineMs: 1_000,
		});

		await expect(pipeline.collect(request)).rejects.toBeInstanceOf(CollectorTimeoutError);
	});

	it("aborts the stalled collector's signal so its own I/O is cancelled too", async () => {
		const { collector, aborted } = cancellable();
		const pipeline = new AttributePipeline([collector], { collectorTimeoutMs: 20 });

		await expect(pipeline.collect(request)).rejects.toBeInstanceOf(CollectorTimeoutError);
		expect(aborted()).toBe(true);
	});

	it("names the collector that stalled and the budget it overran", async () => {
		class SlowStoreCollector implements AttributeCollector {
			collect(): Promise<Attributes> {
				return new Promise<Attributes>(() => {});
			}
		}
		const pipeline = new AttributePipeline([new SlowStoreCollector()], { collectorTimeoutMs: 20 });

		const error = await pipeline.collect(request).catch((cause: unknown) => cause);

		expect(error).toBeInstanceOf(CollectorTimeoutError);
		const timeout = error as CollectorTimeoutError;
		expect(timeout.pipeline).toBe("attribute");
		expect(timeout.limit).toBe("collector");
		expect(timeout.timeoutMs).toBe(20);
		expect(timeout.message).toContain("SlowStoreCollector");
	});

	it("starts a queued collector's budget when it starts, not when the fan-out did", async () => {
		// With a concurrency of 1 the second collector waits for the first. If its
		// timeout ran from the fan-out's start it would be dead on arrival — the
		// bound would punish a collector for the queue rather than for its own
		// latency.
		let secondRan = false;
		const slow: AttributeCollector = {
			collect: async () => {
				await sleep(40);
				return new Map();
			},
		};
		const quick: AttributeCollector = {
			collect: async () => {
				secondRan = true;
				return new Map();
			},
		};
		const pipeline = new AttributePipeline([slow, quick], {
			collectorTimeoutMs: 60,
			deadlineMs: 1_000,
			concurrency: 1,
		});

		await pipeline.collect(request);

		expect(secondRan).toBe(true);
	});

	it("bounds a stalled collector even when nothing is configured", async () => {
		vi.useFakeTimers();
		try {
			const settled = expect(
				new AttributePipeline([hanging()]).collect(request),
			).rejects.toBeInstanceOf(CollectorTimeoutError);
			await vi.advanceTimersByTimeAsync(DEFAULT_COLLECTOR_TIMEOUT_MS);
			await settled;
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("AttributePipeline — end-to-end deadline (#115)", () => {
	it("refuses a fan-out that overruns the deadline though no collector overran its own budget", async () => {
		const slow = (): AttributeCollector => ({
			collect: async () => {
				await sleep(30);
				return new Map();
			},
		});
		const pipeline = new AttributePipeline([slow(), slow(), slow(), slow()], {
			collectorTimeoutMs: 1_000,
			deadlineMs: 50,
			concurrency: 1,
		});

		const error = await pipeline.collect(request).catch((cause: unknown) => cause);

		expect(error).toBeInstanceOf(CollectorTimeoutError);
		const timeout = error as CollectorTimeoutError;
		expect(timeout.limit).toBe("deadline");
		expect(timeout.timeoutMs).toBe(50);
	});

	it("cancels whatever is still running when the deadline expires", async () => {
		const { collector, aborted } = cancellable();
		const pipeline = new AttributePipeline([collector], {
			collectorTimeoutMs: 10_000,
			deadlineMs: 20,
		});

		await expect(pipeline.collect(request)).rejects.toBeInstanceOf(CollectorTimeoutError);
		expect(aborted()).toBe(true);
	});

	it("leaves no timer pending once the fan-out is over", async () => {
		// Every bound is a `setTimeout`, and there are two per collector plus one
		// per fan-out, on every decision. One left uncleared would hold a Node
		// worker open for its full duration and pile up under load — a leak
		// measured in seconds per request, which is exactly the resource problem
		// this module exists to fix rather than to cause.
		vi.useFakeTimers();
		try {
			const quick = (): AttributeCollector => ({ collect: async () => new Map() });
			const before = vi.getTimerCount();

			await new AttributePipeline([quick(), quick(), quick()]).collect(request);
			expect(vi.getTimerCount()).toBe(before);

			// And on the failing path, where the `finally` has to survive a throw.
			const failing: AttributeCollector = {
				collect: async () => {
					throw new Error("attribute store is down");
				},
			};
			await expect(new AttributePipeline([failing, quick()]).collect(request)).rejects.toThrow(
				"attribute store is down",
			);
			expect(vi.getTimerCount()).toBe(before);
		} finally {
			vi.useRealTimers();
		}
	});

	it("ships a deadline no shorter than one collector's budget", () => {
		// A deadline under the per-collector timeout would make the per-collector
		// bound unreachable: every stall would be reported as a deadline, and the
		// error would never name the collector responsible.
		expect(DEFAULT_COLLECT_DEADLINE_MS).toBeGreaterThanOrEqual(DEFAULT_COLLECTOR_TIMEOUT_MS);
	});
});

describe("AttributePipeline — concurrency bound (#115)", () => {
	it("never has more than the configured number of collectors in flight", async () => {
		let inFlight = 0;
		let peak = 0;
		const collector = (): AttributeCollector => ({
			collect: async () => {
				inFlight += 1;
				peak = Math.max(peak, inFlight);
				await sleep(5);
				inFlight -= 1;
				return new Map();
			},
		});
		const pipeline = new AttributePipeline(Array.from({ length: 12 }, collector), {
			concurrency: 3,
			collectorTimeoutMs: 1_000,
			deadlineMs: 5_000,
		});

		await pipeline.collect(request);

		expect(peak).toBe(3);
	});

	it("still runs every collector, and merges them in collector order", async () => {
		const collector = (value: string): AttributeCollector => ({
			collect: async () => {
				await sleep(2);
				return new Map([["scopes", [value]]]);
			},
		});
		const pipeline = new AttributePipeline(
			["a", "b", "c", "d", "e"].map(collector),
			// Below the collector count on purpose: the merge order is the
			// collector list's, not the order they happened to finish in.
			{ concurrency: 2, collectorTimeoutMs: 1_000, deadlineMs: 5_000 },
		);

		const attrs = await pipeline.collect(request);

		expect(attrs.get("scopes")).toEqual(["a", "b", "c", "d", "e"]);
	});

	it("ships a concurrency bound that a normal collector set does not notice", () => {
		expect(DEFAULT_COLLECTOR_CONCURRENCY).toBeGreaterThanOrEqual(4);
	});
});

describe("AttributePipeline — fail closed (#115)", () => {
	it("never returns the attributes it did collect when another collector stalls", async () => {
		const fast: AttributeCollector = {
			collect: async () => new Map([["scopes", ["read:project"]]]),
		};
		const pipeline = new AttributePipeline([fast, hanging()], {
			collectorTimeoutMs: 20,
			deadlineMs: 1_000,
		});

		// The dangerous shape is a pipeline that resolves with what it managed to
		// gather: a missing `scopes` attribute is a *deny* for a scope rule, but a
		// missing rule is an empty rule set — which a deployment that set
		// `onEmptyRuleSet: "allow"` turns into a permit. Partial results must not
		// exist for either pipeline.
		await expect(pipeline.collect(request)).rejects.toBeInstanceOf(CollectorTimeoutError);
	});

	it("cancels the collectors still running when one of them fails", async () => {
		const { collector: sibling, aborted } = cancellable();
		const failing: AttributeCollector = {
			collect: async () => {
				await sleep(5);
				throw new Error("attribute store is down");
			},
		};
		const pipeline = new AttributePipeline([failing, sibling], {
			collectorTimeoutMs: 1_000,
			deadlineMs: 5_000,
		});

		await expect(pipeline.collect(request)).rejects.toThrow("attribute store is down");
		expect(aborted()).toBe(true);
	});

	it("does not invoke a collector whose decision the deadline already ended", async () => {
		// The distinction that matters: not "cancelled after starting" but never
		// started. A collector that passes its signal to `fetch` — the documented
		// way to use it — has already put the request on the wire by the time it
		// could notice `aborted`, and that request is amplification against the
		// dependency whose slowness ended the decision.
		let invoked = 0;
		const slow: AttributeCollector = {
			collect: async () => {
				await sleep(60);
				return new Map();
			},
		};
		const later = (): AttributeCollector => ({
			collect: async () => {
				invoked += 1;
				return new Map();
			},
		});
		const pipeline = new AttributePipeline([slow, later(), later(), later()], {
			collectorTimeoutMs: 1_000,
			deadlineMs: 25,
			concurrency: 1,
		});

		await expect(pipeline.collect(request)).rejects.toBeInstanceOf(CollectorTimeoutError);
		expect(invoked).toBe(0);
	});

	it("blames the deadline, not the collector it never ran", async () => {
		// A skipped collector did not overrun anything — the set ended. Reporting
		// it as that collector's own timeout would send an operator to tune a
		// budget that was never spent.
		const slow: AttributeCollector = {
			collect: async () => {
				await sleep(60);
				return new Map();
			},
		};
		class NeverRanCollector implements AttributeCollector {
			async collect(): Promise<Attributes> {
				return new Map();
			}
		}
		const pipeline = new AttributePipeline([slow, new NeverRanCollector()], {
			collectorTimeoutMs: 1_000,
			deadlineMs: 25,
			concurrency: 1,
		});

		const error = (await pipeline
			.collect(request)
			.catch((cause: unknown) => cause)) as CollectorTimeoutError;

		expect(error.limit).toBe("deadline");
		expect(error.message).not.toContain("NeverRanCollector");
	});

	it("propagates a sibling's failure to the collectors it never let start", async () => {
		// Same guarantee for the other two ways a fan-out ends: the reason is
		// carried through unchanged rather than replaced by a timeout.
		let invoked = 0;
		const failing: AttributeCollector = {
			collect: async () => {
				await sleep(5);
				throw new Error("attribute store is down");
			},
		};
		const later = (): AttributeCollector => ({
			collect: async () => {
				invoked += 1;
				return new Map();
			},
		});
		const pipeline = new AttributePipeline([failing, later(), later()], {
			collectorTimeoutMs: 1_000,
			deadlineMs: 5_000,
			concurrency: 1,
		});

		await expect(pipeline.collect(request)).rejects.toThrow("attribute store is down");
		expect(invoked).toBe(0);
	});

	it("does not start another collector once the fan-out has already failed", async () => {
		let started = 0;
		const failing: AttributeCollector = {
			collect: async () => {
				started += 1;
				throw new Error("attribute store is down");
			},
		};
		const later = (): AttributeCollector => ({
			collect: async () => {
				started += 1;
				return new Map();
			},
		});
		const pipeline = new AttributePipeline([failing, later(), later(), later()], {
			concurrency: 1,
			collectorTimeoutMs: 1_000,
			deadlineMs: 5_000,
		});

		await expect(pipeline.collect(request)).rejects.toThrow("attribute store is down");
		expect(started).toBe(1);
	});
});

describe("collector limits — refused at construction (#115)", () => {
	it.each([
		["a zero timeout", { collectorTimeoutMs: 0 }],
		["a negative timeout", { collectorTimeoutMs: -1 }],
		["a fractional timeout", { collectorTimeoutMs: 1.5 }],
		["NaN", { collectorTimeoutMs: Number.NaN }],
		[
			"an infinite deadline — the unbounded case the knob exists to prevent",
			{
				deadlineMs: Number.POSITIVE_INFINITY,
			},
		],
		["a zero deadline", { deadlineMs: 0 }],
		["a zero concurrency — a fan-out that would run nothing at all", { concurrency: 0 }],
		["a fractional concurrency", { concurrency: 2.5 }],
	])("refuses %s", (_label, limits) => {
		// Refused where it is written, not silently repaired: a concurrency of 0
		// would otherwise resolve every request with no collector having run — an
		// empty attribute map and an empty rule set, which is exactly the
		// fail-open the deadline work exists to close.
		expect(() => new AttributePipeline([], limits)).toThrow(RangeError);
		expect(() => new RulePipeline([], limits)).toThrow(RangeError);
	});

	it("accepts the resolved shape a config boundary produces", () => {
		expect(
			() =>
				new AttributePipeline([], { collectorTimeoutMs: 2_000, deadlineMs: 5_000, concurrency: 8 }),
		).not.toThrow();
	});
});

describe("RulePipeline — collector deadlines (#115)", () => {
	const rule = (code: string): Rule => ({
		ruleType: "scope",
		code,
		message: `Failed: ${code}`,
		verify: () => true,
	});

	it("hands every rule collector an AbortSignal", async () => {
		let seen: AbortSignal | undefined;
		const collector: RuleCollector = {
			collect: async (context) => {
				seen = context.signal;
				return [rule("ok")];
			},
		};

		await new RulePipeline([collector]).collect(request);

		expect(seen).toBeInstanceOf(AbortSignal);
	});

	it("refuses a rule collector that overruns its budget rather than returning fewer rules", async () => {
		const present: RuleCollector = { collect: async () => [rule("ok")] };
		const stalled: RuleCollector = { collect: () => new Promise<Rule[]>(() => {}) };
		const pipeline = new RulePipeline([present, stalled], {
			collectorTimeoutMs: 20,
			deadlineMs: 1_000,
		});

		// The rule pipeline is where a partial result is most dangerous: fewer
		// rules is a *weaker* policy, and no rules at all is an empty rule set.
		await expect(pipeline.collect(request)).rejects.toBeInstanceOf(CollectorTimeoutError);
	});

	it("names the rule pipeline in the failure", async () => {
		const pipeline = new RulePipeline([{ collect: () => new Promise<Rule[]>(() => {}) }], {
			collectorTimeoutMs: 20,
		});

		const error = await pipeline.collect(request).catch((cause: unknown) => cause);

		expect((error as CollectorTimeoutError).pipeline).toBe("rule");
	});

	it("bounds concurrency the same way the attribute pipeline does", async () => {
		let inFlight = 0;
		let peak = 0;
		const collector = (): RuleCollector => ({
			collect: async () => {
				inFlight += 1;
				peak = Math.max(peak, inFlight);
				await sleep(5);
				inFlight -= 1;
				return [];
			},
		});
		const pipeline = new RulePipeline(Array.from({ length: 8 }, collector), {
			concurrency: 2,
			collectorTimeoutMs: 1_000,
			deadlineMs: 5_000,
		});

		await pipeline.collect(request);

		expect(peak).toBe(2);
	});
});
