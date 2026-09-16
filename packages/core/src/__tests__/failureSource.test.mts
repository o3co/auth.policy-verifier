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
 */
import { describe, expect, it } from "vitest";
import { AttributePipeline } from "../AttributePipeline.mjs";
import { CollectorTimeoutError } from "../errors.mjs";
import { evaluate } from "../evaluate.mjs";
import { failureSourceOf } from "../failureSource.mjs";
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

describe("failureSourceOf — collectors (#200)", () => {
	it("names the collector a rejection came from, and leaves the error itself untouched", async () => {
		class EntitlementStoreCollector implements AttributeCollector {
			async collect(): Promise<Attributes> {
				throw outage;
			}
		}
		const outage = new Error("entitlement store is down");
		const pipeline = new AttributePipeline([quiet(), new EntitlementStoreCollector()]);

		const error = await pipeline.collect(request).catch((cause: unknown) => cause);

		// The same object, not a wrapper: a transport that tells a deny from a
		// fault by class — and a caller that matches its own error — sees exactly
		// what the collector threw.
		expect(error).toBe(outage);
		expect(failureSourceOf(error)).toEqual({
			kind: "collector",
			pipeline: "attribute",
			collector: "attribute.collectors[1] (EntitlementStoreCollector)",
		});
	});

	it("names a collector with no class of its own by its position, in the rule pipeline too", async () => {
		const outage = new Error("rule store is down");
		const failing: RuleCollector = { collect: () => Promise.reject(outage) };

		const error = await new RulePipeline([failing]).collect(request).catch((c: unknown) => c);

		expect(failureSourceOf(error)).toEqual({
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

		const error = await new AttributePipeline([failing]).collect(request).catch((c: unknown) => c);

		expect(error).toBe(outage);
		expect(failureSourceOf(error)).toMatchObject({ collector: "attribute.collectors[0]" });
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

		const error = await pipeline.collect(request).catch((c: unknown) => c);

		expect(error).toBe(outage);
		expect(failureSourceOf(error)).toMatchObject({
			collector: "attribute.collectors[1] (FailingCollector)",
		});
	});

	it("attributes nothing to the caller's own abort reason", async () => {
		const controller = new AbortController();
		const reason = new Error("the caller went away");
		const collecting = new AttributePipeline([cancellable()]).collect({
			...request,
			signal: controller.signal,
		});

		await sleep(5);
		controller.abort(reason);

		await expect(collecting).rejects.toBe(reason);
		expect(failureSourceOf(reason)).toBeUndefined();
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

	it("cannot name a collector that rejects with something other than an object", async () => {
		// The attribution is kept beside the error, keyed by it, and a primitive
		// cannot be a key. The collector's rejection still surfaces unchanged.
		const failing: AttributeCollector = { collect: () => Promise.reject("store is down") };

		const error = await new AttributePipeline([failing]).collect(request).catch((c: unknown) => c);

		expect(error).toBe("store is down");
		expect(failureSourceOf(error)).toBeUndefined();
	});

	it("answers undefined for an error no pipeline produced", () => {
		expect(failureSourceOf(new Error("unrelated"))).toBeUndefined();
		expect(failureSourceOf(undefined)).toBeUndefined();
	});
});

describe("failureSourceOf — rules (#200)", () => {
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

		await expect(evaluate(attrs, [rule])).rejects.toBe(fault);
		expect(failureSourceOf(fault)).toEqual({
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

		await expect(evaluate(attrs, [rule])).rejects.toBe(fault);
		expect(failureSourceOf(fault)).toEqual({ kind: "rule", ruleType: "cedar", code: "cedar_deny" });
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

		await expect(evaluate(attrs, [rule])).rejects.toBe(fault);
		expect(failureSourceOf(fault)).toMatchObject({ kind: "rule", ruleType: "cedar" });
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

		const pending = evaluate(attrs, [rule], { signal: controller.signal });
		controller.abort(reason);

		await expect(pending).rejects.toBe(reason);
		expect(failureSourceOf(reason)).toBeUndefined();
	});
});
