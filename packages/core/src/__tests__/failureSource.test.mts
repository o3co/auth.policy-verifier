// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * #200: which collector — or which rule — a failure came from.
 *
 * A collector that rejects fails the decision, and the transport answers it as
 * a 500 logged `verify_internal_error`. Before this, that line carried the error
 * and nothing else: the operator paged at 3 a.m. had to read `err.message` and
 * guess which of the configured fact sources wrote it. The runner is the one
 * place that knows, so it records the attribution — and records it BESIDE the
 * error rather than wrapping it, because `pipeline.collect` is documented to
 * reject with whatever the collector rejected with, and a transport tells a
 * deny from a fault by that error's class.
 *
 * Beside it in a `FailureRecord` the caller owns — one per decision — and not
 * in anything process-wide: an error object is not a request, and two
 * decisions failing on one shared rejection must each get their own answer.
 */
import { describe, expect, it } from "vitest";
import { AttributePipeline } from "../AttributePipeline.mjs";
import { CollectorTimeoutError } from "../errors.mjs";
import { evaluate } from "../evaluate.mjs";
import { FailureRecord } from "../failureSource.mjs";
import { RulePipeline } from "../RulePipeline.mjs";
import type {
	AsyncRule,
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

const quiet = (): AttributeCollector => ({ collect: async () => new Map() });

/** Rejects with its signal's reason when that aborts — the collector that honours `signal`. */
const cancellable = (): AttributeCollector => ({
	collect: (context) =>
		new Promise<Attributes>((_, reject) => {
			context.signal.addEventListener("abort", () => reject(context.signal.reason), {
				once: true,
			});
		}),
});

describe("FailureRecord — collectors (#200)", () => {
	it("names the collector a rejection came from, and leaves the error itself untouched", async () => {
		class EntitlementStoreCollector implements AttributeCollector {
			async collect(): Promise<Attributes> {
				throw outage;
			}
		}
		const outage = new Error("entitlement store is down");
		const pipeline = new AttributePipeline([quiet(), new EntitlementStoreCollector()]);

		const failures = new FailureRecord();
		const error = await pipeline.collect(request, { failures }).catch((cause: unknown) => cause);

		// The same object, not a wrapper: a transport that tells a deny from a
		// fault by class — and a caller that matches its own error — sees exactly
		// what the collector threw.
		expect(error).toBe(outage);
		expect(failures.sourceOf(error)).toEqual({
			kind: "collector",
			pipeline: "attribute",
			collector: "attribute.collectors[1] (EntitlementStoreCollector)",
		});
	});

	it("names a collector with no class of its own by its position, in the rule pipeline too", async () => {
		const outage = new Error("rule store is down");
		const failing: RuleCollector = { collect: () => Promise.reject(outage) };

		const failures = new FailureRecord();
		const error = await new RulePipeline([failing])
			.collect(request, { failures })
			.catch((c: unknown) => c);

		expect(failures.sourceOf(error)).toEqual({
			kind: "collector",
			pipeline: "rule",
			collector: "rule.collectors[0]",
		});
	});

	it("names a collector that throws synchronously rather than rejecting", async () => {
		const outage = new Error("thrown before any await");
		const failing: AttributeCollector = {
			collect: () => {
				throw outage;
			},
		};

		const failures = new FailureRecord();
		const error = await new AttributePipeline([failing])
			.collect(request, { failures })
			.catch((c: unknown) => c);

		expect(error).toBe(outage);
		expect(failures.sourceOf(error)).toMatchObject({ collector: "attribute.collectors[0]" });
	});

	it("does not blame a sibling that rejected with the failure it was cancelled for", async () => {
		// A collector that honours its signal rejects with the signal's reason —
		// which, once a sibling has failed the decision, IS the sibling's error.
		// The attribution must stay with the collector that actually failed.
		class FailingCollector implements AttributeCollector {
			async collect(): Promise<Attributes> {
				await sleep(5);
				throw outage;
			}
		}
		const outage = new Error("store is down");
		const pipeline = new AttributePipeline([cancellable(), new FailingCollector()]);

		const failures = new FailureRecord();
		const error = await pipeline.collect(request, { failures }).catch((c: unknown) => c);

		expect(error).toBe(outage);
		expect(failures.sourceOf(error)).toMatchObject({
			collector: "attribute.collectors[1] (FailingCollector)",
		});
	});

	it("attributes nothing to the caller's own abort reason", async () => {
		const controller = new AbortController();
		const reason = new Error("the caller went away");
		const failures = new FailureRecord();
		const collecting = new AttributePipeline([cancellable()]).collect(
			{ ...request, signal: controller.signal },
			{ failures },
		);

		await sleep(5);
		controller.abort(reason);

		await expect(collecting).rejects.toBe(reason);
		expect(failures.sourceOf(reason)).toBeUndefined();
	});

	it("names a timed-out collector on the timeout itself, in the same spelling", async () => {
		class SlowStoreCollector implements AttributeCollector {
			collect(): Promise<Attributes> {
				return new Promise<Attributes>(() => {});
			}
		}
		const pipeline = new AttributePipeline([quiet(), new SlowStoreCollector()], {
			collectorTimeoutMs: 20,
		});

		const error = (await pipeline
			.collect(request)
			.catch((c: unknown) => c)) as CollectorTimeoutError;

		expect(error).toBeInstanceOf(CollectorTimeoutError);
		expect(error.collector).toBe("attribute.collectors[1] (SlowStoreCollector)");
	});

	it("names a collector that rejects with something other than an Error", async () => {
		const failing: AttributeCollector = { collect: () => Promise.reject("store is down") };

		const failures = new FailureRecord();
		const error = await new AttributePipeline([failing])
			.collect(request, { failures })
			.catch((c: unknown) => c);

		expect(error).toBe("store is down");
		expect(failures.sourceOf(error)).toMatchObject({ collector: "attribute.collectors[0]" });
	});

	it("answers undefined for an error no pipeline produced", () => {
		const failures = new FailureRecord();
		expect(failures.sourceOf(new Error("unrelated"))).toBeUndefined();
		expect(failures.sourceOf(undefined)).toBeUndefined();
	});

	it("still rejects unchanged, and records nothing, when no record is handed in", async () => {
		const outage = new Error("store is down");
		const failing: AttributeCollector = { collect: () => Promise.reject(outage) };

		await expect(new AttributePipeline([failing]).collect(request)).rejects.toBe(outage);
	});
});

describe("FailureRecord — rules (#200)", () => {
	const attrs: Attributes = new Map();

	it("names the synchronous rule whose verify threw, and rethrows the error unchanged", async () => {
		const fault = new TypeError("cannot read properties of undefined");
		const rule: Rule = {
			ruleType: "tenant",
			code: "wrong_tenant",
			message: "Wrong tenant",
			verify: () => {
				throw fault;
			},
		};

		const failures = new FailureRecord();
		await expect(evaluate(attrs, [rule], { failures })).rejects.toBe(fault);
		expect(failures.sourceOf(fault)).toEqual({
			kind: "rule",
			ruleType: "tenant",
			code: "wrong_tenant",
		});
	});

	it("names the asynchronous rule whose decide rejected", async () => {
		const fault = new Error("engine answered garbage");
		const rule: AsyncRule = {
			ruleType: "cedar",
			code: "cedar_deny",
			message: "Denied by Cedar policy",
			async: true,
			decide: () => Promise.reject(fault),
		};

		const failures = new FailureRecord();
		await expect(evaluate(attrs, [rule], { failures })).rejects.toBe(fault);
		expect(failures.sourceOf(fault)).toEqual({
			kind: "rule",
			ruleType: "cedar",
			code: "cedar_deny",
		});
	});

	it("names the asynchronous rule whose decide threw before returning a promise", async () => {
		const fault = new Error("thrown synchronously");
		const rule: AsyncRule = {
			ruleType: "cedar",
			code: "cedar_deny",
			message: "Denied by Cedar policy",
			async: true,
			decide: () => {
				throw fault;
			},
		};

		const failures = new FailureRecord();
		await expect(evaluate(attrs, [rule], { failures })).rejects.toBe(fault);
		expect(failures.sourceOf(fault)).toMatchObject({ kind: "rule", ruleType: "cedar" });
	});

	it("attributes nothing to the caller's abort reason, even when the rule rejects with it", async () => {
		const controller = new AbortController();
		const reason = new Error("the caller went away");
		const rule: AsyncRule = {
			ruleType: "cedar",
			code: "cedar_deny",
			message: "Denied by Cedar policy",
			async: true,
			decide: (_attrs, signal) =>
				new Promise<boolean>((_, reject) => {
					signal.addEventListener("abort", () => reject(signal.reason), { once: true });
				}),
		};

		const failures = new FailureRecord();
		const pending = evaluate(attrs, [rule], { signal: controller.signal, failures });
		controller.abort(reason);

		await expect(pending).rejects.toBe(reason);
		expect(failures.sourceOf(reason)).toBeUndefined();
	});
});

describe("FailureRecord — one shared rejection, several failures (#200 review)", () => {
	/** A rejection several collectors await: rejected once, after all are waiting. */
	function shared() {
		const error = new Error("shared downstream call failed");
		let reject!: (reason: unknown) => void;
		const promise = new Promise<never>((_, r) => {
			reject = r;
		});
		promise.catch(() => {});
		return { error, promise, fail: () => reject(error) };
	}

	it("gives each concurrent decision its own answer", async () => {
		// The defect a process-wide association had: the rule pipeline's record
		// landed after the attribute pipeline's and before either caller caught,
		// so both decisions named the rule collector.
		const downstream = shared();
		class SharedClientCollector implements AttributeCollector {
			async collect(): Promise<Attributes> {
				return downstream.promise;
			}
		}
		const sharedRules: RuleCollector = { collect: async () => downstream.promise };
		const first = new FailureRecord();
		const second = new FailureRecord();

		const attributes = new AttributePipeline([new SharedClientCollector()])
			.collect(request, { failures: first })
			.catch((c: unknown) => c);
		const rules = new RulePipeline([quietRules(), sharedRules])
			.collect(request, { failures: second })
			.catch((c: unknown) => c);
		await sleep(1);
		downstream.fail();

		expect(await attributes).toBe(downstream.error);
		expect(await rules).toBe(downstream.error);
		expect(first.sourceOf(downstream.error)).toMatchObject({
			collector: "attribute.collectors[0] (SharedClientCollector)",
		});
		expect(second.sourceOf(downstream.error)).toMatchObject({ collector: "rule.collectors[1]" });
	});

	it("keeps the first source recorded when one decision fails twice with the same object", async () => {
		const downstream = shared();
		const failures = new FailureRecord();
		const waiting = (): AttributeCollector => ({ collect: async () => downstream.promise });

		const attributes = new AttributePipeline([waiting()])
			.collect(request, { failures })
			.catch((c: unknown) => c);
		const rules = new RulePipeline([{ collect: async () => downstream.promise }])
			.collect(request, { failures })
			.catch((c: unknown) => c);
		await sleep(1);
		downstream.fail();
		await Promise.all([attributes, rules]);

		// Both pipelines recorded; the first stays. It is the collector that was
		// waiting first, and so the first whose rejection landed.
		expect(failures.sourceOf(downstream.error)).toEqual({
			kind: "collector",
			pipeline: "attribute",
			collector: "attribute.collectors[0]",
		});
	});
});

function quietRules(): RuleCollector {
	return { collect: async () => [] };
}

describe("FailureRecord — timeouts are recorded by what raised them (#200 review)", () => {
	it("records a collector's own timeout against that collector", async () => {
		class SlowStoreCollector implements AttributeCollector {
			collect(): Promise<Attributes> {
				return new Promise<Attributes>(() => {});
			}
		}
		const failures = new FailureRecord();

		const error = await new AttributePipeline([quiet(), new SlowStoreCollector()], {
			collectorTimeoutMs: 20,
		})
			.collect(request, { failures })
			.catch((c: unknown) => c);

		expect(error).toBeInstanceOf(CollectorTimeoutError);
		expect(failures.sourceOf(error)).toEqual({
			kind: "collector",
			pipeline: "attribute",
			collector: "attribute.collectors[1] (SlowStoreCollector)",
		});
	});

	it("records a fan-out deadline against the pipeline, naming no collector", async () => {
		const slow: RuleCollector = {
			collect: async () => {
				await sleep(40);
				return [];
			},
		};
		const failures = new FailureRecord();

		const error = await new RulePipeline([slow], { collectorTimeoutMs: 1_000, deadlineMs: 15 })
			.collect(request, { failures })
			.catch((c: unknown) => c);

		expect(error).toBeInstanceOf(CollectorTimeoutError);
		expect(failures.sourceOf(error)).toEqual({ kind: "deadline", pipeline: "rule" });
	});

	it("records a CollectorTimeoutError a collector built itself as that collector's failure, not as the one it names", async () => {
		// The class is public: a collector can throw one claiming any name at
		// all. What the record says is what the runner saw — this position.
		const forged: AttributeCollector = {
			collect: () =>
				Promise.reject(
					new CollectorTimeoutError({
						pipeline: "attribute",
						limit: "collector",
						timeoutMs: 1,
						collector: "Bearer eyJhbGciOiJIUzI1NiJ9.secret",
					}),
				),
		};
		const failures = new FailureRecord();

		const error = await new AttributePipeline([forged])
			.collect(request, { failures })
			.catch((c: unknown) => c);

		expect(failures.sourceOf(error)).toEqual({
			kind: "collector",
			pipeline: "attribute",
			collector: "attribute.collectors[0]",
		});
	});

	it("records a rule timeout, and a rule the spent phase never started, against the rule", async () => {
		const never = (code: string): AsyncRule => ({
			ruleType: "cedar",
			code,
			message: "Denied by Cedar policy",
			async: true,
			decide: () => new Promise<boolean>(() => {}),
		});
		const failures = new FailureRecord();

		const own = await evaluate(new Map(), [never("first")], { ruleTimeoutMs: 15, failures }).catch(
			(c: unknown) => c,
		);
		const phase = await evaluate(new Map(), [never("a"), { ...never("b"), ruleType: "other" }], {
			ruleTimeoutMs: 1_000,
			evaluateDeadlineMs: 15,
			failures,
		}).catch((c: unknown) => c);

		expect(failures.sourceOf(own)).toEqual({ kind: "rule", ruleType: "cedar", code: "first" });
		expect(failures.sourceOf(phase)).toEqual({ kind: "rule", ruleType: "cedar", code: "a" });
	});
});

describe("describing a collector (#200 review)", () => {
	it.each([
		["a name that is not an identifier", "Bearer eyJhbGciOiJIUzI1NiJ9"],
		["a name longer than any class name", `C${"x".repeat(64)}`],
	])("leaves out %s and names the position only", async (_what, name) => {
		class Renamed implements AttributeCollector {
			async collect(): Promise<Attributes> {
				throw new Error("down");
			}
		}
		Object.defineProperty(Renamed, "name", { value: name });
		const failures = new FailureRecord();

		const error = await new AttributePipeline([new Renamed()])
			.collect(request, { failures })
			.catch((c: unknown) => c);

		expect(failures.sourceOf(error)).toMatchObject({ collector: "attribute.collectors[0]" });
	});
});
