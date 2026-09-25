// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * #244: which policy revision a decision was evaluated against — on the audit
 * line always, on the wire when the deployment says so.
 *
 * The router adds nothing of its own here. A rule reports the evaluation
 * behind its answer — to the reporter core hands it for that one call; it still
 * answers a boolean — `evaluate()` lands it on that invocation's outcome, and
 * the two projections of one `Decision` — the `decision` event and the
 * response — either carry it or drop it. So what these tests hold the router
 * to is that both projections say the same thing, that the response says it
 * only when configured to, and that nothing ever reports a revision for a
 * decision no policy made.
 */

import { DotNotationResourceParser } from "@o3co/auth.policy-verifier.builtins";
import {
	type AnyRule,
	AttributePipeline,
	type Decision,
	type EventLogger,
	type RuleCollector,
	type RuleEvaluation,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import type { TokenAuthenticator } from "#/auth/tokenAuthenticator.mjs";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import {
	checkEvaluationInResponse,
	EVALUATION_IN_RESPONSE_VALUES,
} from "#/config/evaluationInResponse.mjs";
import { decisionEvent } from "#/observability/decisionEvent.mjs";
import { createVerifyRouter, type VerifyRouterConfig } from "#/routes/verify.mjs";

const REVISION_A = `sha256:${"a".repeat(64)}`;
const REVISION_B = `sha256:${"b".repeat(64)}`;

const authenticator: TokenAuthenticator = {
	authenticate: async () => ({ ok: true, subject: { sub: "user-1" }, credential: "token" }),
};

interface Captured {
	obj: Record<string, unknown>;
	msg: string;
}

function capture(): { events: Captured[]; logger: EventLogger } {
	const events: Captured[] = [];
	const push = (obj: Record<string, unknown>, msg: string) => events.push({ obj, msg });
	return { events, logger: { info: push, warn: push, error: push } };
}

const decisionLines = (events: Captured[]) =>
	events.filter((event) => event.msg === "decision").map((event) => event.obj);

/** What a staged rule does for one request: its answer, and what it reports, if anything. */
type Staged = boolean | { passed: boolean; evaluation: RuleEvaluation };

/** A policy-backed rule: reports the evaluation it is given, and answers the boolean. */
function reporting(
	ruleType: string,
	answer: (action: string) => Staged,
	code = `${ruleType}_deny`,
): RuleCollector {
	return {
		async collect(context) {
			const action = context.action;
			const rule: AnyRule = {
				ruleType,
				code,
				message: `Denied by ${ruleType}`,
				verify: (_attrs, report) => {
					const staged = answer(action);
					if (typeof staged === "boolean") return staged;
					report?.(staged.evaluation);
					return staged.passed;
				},
			};
			return [rule];
		},
	};
}

const completed = (revision: string): RuleEvaluation => ({ status: "completed", revision });

function appWith(
	collectors: RuleCollector[],
	overrides: Partial<VerifyRouterConfig> = {},
): { app: express.Express; events: Captured[] } {
	const { events, logger } = capture();
	const app = express();
	app.use(
		createVerifyRouter({
			authenticator,
			logger,
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([]),
			rulePipeline: new RulePipeline(collectors),
			...overrides,
		}),
	);
	return { app, events };
}

const verify = (app: express.Express, body: unknown, path = "/verify") =>
	request(app)
		.post(path)
		.set("Authorization", "Bearer token")
		.send(body as object);

/** Every `evaluation` anywhere in a response body's reason. */
function evaluationsIn(body: { reason: Decision["reason"] }): unknown[] {
	return body.reason.groups.flatMap((group) =>
		group.evaluated.flatMap((outcome) => ("evaluation" in outcome ? [outcome.evaluation] : [])),
	);
}

const cedarLike = reporting("cedar", (action) =>
	action === "read"
		? { passed: true, evaluation: completed(REVISION_A) }
		: { passed: false, evaluation: completed(REVISION_A) },
);

describe("the decision event — always carries what the rules reported", () => {
	it("lists each reported evaluation beside the rule that reported it, on an allow", async () => {
		const { app, events } = appWith([cedarLike, reporting("scope", () => true)]);
		await verify(app, { resource: "project:1", action: "read" }).expect(200);
		const [line] = decisionLines(events);
		expect(line.decision).toBe("allow");
		// The builtin-style rule reported nothing and is not listed: it has no
		// policy source to name, and an entry for it would have to invent one.
		expect(line.evaluations).toEqual([
			{ ruleType: "cedar", code: "cedar_deny", passed: true, evaluation: completed(REVISION_A) },
		]);
	});

	it("carries the same on a policy-deny", async () => {
		const { app, events } = appWith([cedarLike]);
		await verify(app, { resource: "project:1", action: "delete" }).expect(403);
		const [line] = decisionLines(events);
		expect(line).toMatchObject({ decision: "deny", code: "cedar_deny" });
		expect(line.evaluations).toEqual([
			{ ruleType: "cedar", code: "cedar_deny", passed: false, evaluation: completed(REVISION_A) },
		]);
	});

	it("says which way each rule answered — a revision that refused is not one that authorized", async () => {
		// One OR group, two policy sources: the first forbids, the second
		// permits, and the decision is an allow. Without `passed` the line reads
		// as two revisions standing behind the allow, and the two entries — same
		// `ruleType`, same `code` — could be told apart only by position.
		const forbids = reporting(
			"cedar",
			() => ({ passed: false, evaluation: completed(REVISION_A) }),
			"cedar_deny",
		);
		const permits = reporting(
			"cedar",
			() => ({ passed: true, evaluation: completed(REVISION_B) }),
			"cedar_deny",
		);
		const { app, events } = appWith([forbids, permits], { evaluationInResponse: "include" });
		const res = await verify(app, { resource: "project:1", action: "read" }).expect(200);
		const [line] = decisionLines(events);
		expect(line.decision).toBe("allow");
		expect(line.evaluations).toEqual([
			{ ruleType: "cedar", code: "cedar_deny", passed: false, evaluation: completed(REVISION_A) },
			{ ruleType: "cedar", code: "cedar_deny", passed: true, evaluation: completed(REVISION_B) },
		]);
		// …which is the response's own account, outcome for outcome.
		expect(
			(line.evaluations as Record<string, unknown>[]).map(
				({ ruleType: _ruleType, ...rest }) => rest,
			),
		).toEqual(
			res.body.reason.groups[0].evaluated.map(
				({ message: _message, ...rest }: Record<string, unknown>) => rest,
			),
		);
	});

	it("keeps a denial no policy produced apart from a policy's, under the same code", async () => {
		const notInvoked = reporting("cedar", () => ({
			passed: false,
			evaluation: { status: "not_invoked" },
		}));
		const { app, events } = appWith([notInvoked]);
		await verify(app, { resource: "project:1", action: "read" }).expect(403);
		const [line] = decisionLines(events);
		expect(line).toMatchObject({ decision: "deny", code: "cedar_deny" });
		expect(line.evaluations).toEqual([
			{
				ruleType: "cedar",
				code: "cedar_deny",
				passed: false,
				evaluation: { status: "not_invoked" },
			},
		]);
		expect(JSON.stringify(line)).not.toContain("sha256:");
	});

	it("says so when what was evaluated could not be established, and what was loaded instead", async () => {
		const remote = reporting("cedar", () => ({
			passed: true,
			evaluation: { status: "completed", revision: null, loadedRevision: REVISION_A },
		}));
		const { app, events } = appWith([remote]);
		await verify(app, { resource: "project:1", action: "read" }).expect(200);
		expect(decisionLines(events)[0].evaluations).toEqual([
			{
				ruleType: "cedar",
				code: "cedar_deny",
				passed: true,
				evaluation: { status: "completed", revision: null, loadedRevision: REVISION_A },
			},
		]);
	});

	it("does not collapse two policy sources into one revision", async () => {
		const other = reporting("cedar-b", () => ({ passed: true, evaluation: completed(REVISION_B) }));
		const { app, events } = appWith([cedarLike, other]);
		await verify(app, { resource: "project:1", action: "read" }).expect(200);
		expect(decisionLines(events)[0].evaluations).toEqual([
			{ ruleType: "cedar", code: "cedar_deny", passed: true, evaluation: completed(REVISION_A) },
			{
				ruleType: "cedar-b",
				code: "cedar-b_deny",
				passed: true,
				evaluation: completed(REVISION_B),
			},
		]);
	});

	it("has no evaluations key when no rule reported one — the line is what it was", () => {
		const event = decisionEvent({
			decision: {
				decision: "allow",
				reason: {
					groups: [
						{
							ruleType: "scope",
							passed: true,
							evaluated: [{ code: "invalid_scope", message: "m", passed: true }],
							satisfiedBy: { code: "invalid_scope", message: "m", passed: true },
						},
					],
				},
			},
			resource: "project:1",
			action: "read",
			durationMs: 1,
		});
		expect(event).not.toHaveProperty("evaluations");
	});

	it("hands a rule the core's own reporter — one that bounds determining policies (#199)", async () => {
		// A rule that follows the contract names them only through its reporter;
		// under the server it always can, because nothing stands between the rule
		// and core's evaluate().
		const asking: RuleCollector = {
			async collect() {
				const rule: AnyRule = {
					ruleType: "cedar",
					code: "cedar_deny",
					message: "Denied by cedar",
					verify: (_attrs, report) => {
						report?.({
							status: "completed",
							revision: REVISION_A,
							...report?.boundDeterminingPolicies?.(["20-forbid-delete"]),
						});
						return false;
					},
				};
				return [rule];
			},
		};
		const { app, events } = appWith([asking]);
		await verify(app, { resource: "project:1", action: "delete" }).expect(403);
		expect(decisionLines(events)[0].evaluations).toEqual([
			expect.objectContaining({
				evaluation: {
					status: "completed",
					revision: REVISION_A,
					determiningPolicies: ["20-forbid-delete"],
				},
			}),
		]);
	});
});

describe("the response — carries it only when the deployment says so", () => {
	it("omits every evaluation by default, leaving the outcome keys what they were", async () => {
		const { app } = appWith([cedarLike]);
		const res = await verify(app, { resource: "project:1", action: "read" }).expect(200);
		expect(evaluationsIn(res.body)).toEqual([]);
		expect(Object.keys(res.body.reason.groups[0].evaluated[0]).sort()).toEqual([
			"code",
			"message",
			"passed",
		]);
		expect(Object.keys(res.body.reason.groups[0].satisfiedBy).sort()).toEqual([
			"code",
			"message",
			"passed",
		]);
		expect(res.text).not.toContain("sha256:");
	});

	it("includes them under evaluationInResponse = include, on allow and deny, matching the event", async () => {
		const { app, events } = appWith([cedarLike], { evaluationInResponse: "include" });
		const allow = await verify(app, { resource: "project:1", action: "read" }).expect(200);
		const deny = await verify(app, { resource: "project:1", action: "delete" }).expect(403);

		expect(allow.body.reason.groups[0].evaluated[0].evaluation).toEqual(completed(REVISION_A));
		expect(allow.body.reason.groups[0].satisfiedBy.evaluation).toEqual(completed(REVISION_A));
		expect(deny.body.reason.groups[0].evaluated[0].evaluation).toEqual(completed(REVISION_A));
		// Existing consumers' fields are untouched by the addition.
		expect(deny.body).toMatchObject({ decision: "deny", code: "cedar_deny" });

		for (const [index, res] of [allow, deny].entries()) {
			const onTheLine = (decisionLines(events)[index].evaluations as { evaluation: unknown }[]).map(
				(entry) => entry.evaluation,
			);
			expect(onTheLine).toEqual(evaluationsIn(res.body));
		}
	});

	// #199: the policies that determined an answer ride the same evaluation, so
	// the same switch governs them — on the audit line always, on the response
	// only when the deployment opts in. A policy id is internal structure.
	it("carries the determining policies the same way — on the line always, in the response only under include (#199)", async () => {
		const determining = reporting("cedar", (action) =>
			action === "read"
				? {
						passed: true,
						evaluation: {
							status: "completed",
							revision: REVISION_A,
							determiningPolicies: ["10-permit-read"],
						},
					}
				: {
						passed: false,
						evaluation: {
							status: "completed",
							revision: REVISION_A,
							determiningPolicies: ["20-forbid-delete"],
						},
					},
		);

		const omitting = appWith([determining]);
		const hidden = await verify(omitting.app, { resource: "project:1", action: "delete" }).expect(
			403,
		);
		expect(hidden.text).not.toContain("20-forbid-delete");
		expect(decisionLines(omitting.events)[0].evaluations).toEqual([
			expect.objectContaining({
				evaluation: {
					status: "completed",
					revision: REVISION_A,
					determiningPolicies: ["20-forbid-delete"],
				},
			}),
		]);

		const including = appWith([determining], { evaluationInResponse: "include" });
		const allow = await verify(including.app, { resource: "project:1", action: "read" }).expect(
			200,
		);
		const deny = await verify(including.app, { resource: "project:1", action: "delete" }).expect(
			403,
		);
		expect(allow.body.reason.groups[0].evaluated[0].evaluation.determiningPolicies).toEqual([
			"10-permit-read",
		]);
		expect(deny.body.reason.groups[0].evaluated[0].evaluation.determiningPolicies).toEqual([
			"20-forbid-delete",
		]);
		// The coarse code is what it was: the detail is beside it, not instead of it.
		expect(deny.body).toMatchObject({ decision: "deny", code: "cedar_deny" });
	});

	it("attributes each batch entry to its own evaluation, in order, sharing one request id", async () => {
		// The revision a rule reports is per invocation; a batch is N of them.
		// Entries alternate between two sources here so that stamping the batch
		// with whichever came last would show.
		const alternating = reporting("cedar", (action) => ({
			passed: true,
			evaluation: completed(action === "read" ? REVISION_A : REVISION_B),
		}));
		const { app, events } = appWith([alternating], {
			evaluationInResponse: "include",
			batchConcurrency: 4,
		});
		const actions = ["read", "write", "read", "write", "read", "write"];
		const res = await verify(
			app,
			{ decisions: actions.map((action) => ({ resource: "project:1", action })) },
			"/verify/batch",
		)
			.set("x-request-id", "batch-244")
			.expect(200);

		const expected = actions.map((action) =>
			completed(action === "read" ? REVISION_A : REVISION_B),
		);
		expect(
			res.body.decisions.map((entry: { reason: Decision["reason"] }) => evaluationsIn(entry)[0]),
		).toEqual(expected);

		// One line per entry, each joinable to the response by request id, action
		// and its own evaluation.
		const lines = decisionLines(events);
		expect(lines).toHaveLength(actions.length);
		for (const line of lines) {
			expect(line.requestId).toBe("batch-244");
			expect(line.evaluations).toEqual([
				{
					ruleType: "cedar",
					code: "cedar_deny",
					passed: true,
					evaluation: completed(line.action === "read" ? REVISION_A : REVISION_B),
				},
			]);
		}
	});
});

describe("decisions no policy made — no revision, on either surface", () => {
	const include = { evaluationInResponse: "include" } as const;

	it("a rule that timed out: the evaluator was asked and did not answer", async () => {
		const hanging: RuleCollector = {
			async collect() {
				return [
					{
						ruleType: "cedar",
						code: "cedar_deny",
						message: "Denied by cedar",
						async: true,
						decide: () => new Promise<boolean>(() => {}),
					},
				];
			},
		};
		const { app, events } = appWith([hanging], { ...include, ruleTimeoutMs: 5 });
		const res = await verify(app, { resource: "project:1", action: "read" }).expect(403);
		expect(res.body).toMatchObject({ decision: "deny", code: "rule_timeout" });
		expect(res.body.reason).toEqual({ groups: [] });
		expect(decisionLines(events)[0]).not.toHaveProperty("evaluations");
	});

	it("no applicable rule, and an allow-on-empty deployment", async () => {
		const none: RuleCollector = { collect: async () => [] };
		const denied = appWith([none], include);
		const res = await verify(denied.app, { resource: "project:1", action: "read" }).expect(403);
		expect(res.body).toMatchObject({ code: "no_applicable_rule", reason: { groups: [] } });
		expect(decisionLines(denied.events)[0]).not.toHaveProperty("evaluations");

		const allowed = appWith([none], { ...include, evaluateOptions: { onEmptyRuleSet: "allow" } });
		const open = await verify(allowed.app, { resource: "project:1", action: "read" }).expect(200);
		expect(open.body.reason).toEqual({ groups: [] });
		expect(decisionLines(allowed.events)[0]).not.toHaveProperty("evaluations");
	});

	it("a request refused before evaluation is not a decision at all", async () => {
		const { app, events } = appWith([cedarLike], include);
		const res = await verify(app, { resource: "project:1" }).expect(400);
		expect(Object.keys(res.body).sort()).toEqual(["code", "decision", "message"]);
		expect(decisionLines(events)).toEqual([]);
	});

	it("a rule whose report does not read is a fault, and its text reaches neither surface", async () => {
		const leaking = reporting("cedar", () => ({
			passed: true,
			evaluation: {
				status: "completed",
				revision: "/etc/verifier/policies/prod",
			} as unknown as RuleEvaluation,
		}));
		const { app, events } = appWith([leaking], include);
		const res = await verify(app, { resource: "project:1", action: "read" }).expect(500);
		expect(res.body).toMatchObject({ decision: "deny", code: "internal_error" });
		expect(res.text).not.toContain("/etc/verifier");
		expect(JSON.stringify(events)).not.toContain("/etc/verifier");
		expect(events.find((event) => event.msg === "verify_internal_error")?.obj).toMatchObject({
			category: "rule_threw",
			rule: { ruleType: "cedar", code: "cedar_deny" },
		});
	});
});

describe("verify.evaluationInResponse — one check, two boundaries", () => {
	it("defaults to omit at both", () => {
		expect(checkEvaluationInResponse(undefined)).toEqual({ ok: true, value: "omit" });
		expect(AppConfigSchema.parse(minimalConfig()).verify.evaluationInResponse).toBe("omit");
		expect(
			AppConfigSchema.parse({ ...minimalConfig(), verify: {} }).verify.evaluationInResponse,
		).toBe("omit");
	});

	it.each([...EVALUATION_IN_RESPONSE_VALUES])("accepts %s at both", (value) => {
		expect(checkEvaluationInResponse(value)).toEqual({ ok: true, value });
		expect(
			AppConfigSchema.parse({ ...minimalConfig(), verify: { evaluationInResponse: value } }).verify
				.evaluationInResponse,
		).toBe(value);
		expect(() => appWith([cedarLike], { evaluationInResponse: value })).not.toThrow();
	});

	it.each([["included"], [true], [null], [""]])(
		"refuses %j at both, naming the same key in the same words",
		(value) => {
			const check = checkEvaluationInResponse(value);
			if (check.ok) throw new Error("expected a refusal");
			expect(check.message).toMatch(/^verify\.evaluationInResponse must be one of omit, include/);

			const parsed = AppConfigSchema.safeParse({
				...minimalConfig(),
				verify: { evaluationInResponse: value },
			});
			expect(parsed.success).toBe(false);
			if (!parsed.success) {
				const issue = parsed.error.issues.find(
					(candidate) => candidate.path.join(".") === "verify.evaluationInResponse",
				);
				expect(issue?.message).toBe(check.message);
			}

			expect(() => appWith([cedarLike], { evaluationInResponse: value as never })).toThrow(
				`createVerifyRouter: ${check.message}`,
			);
		},
	);
});

/** The least `AppConfigSchema` parses: a verifying JWT block and nothing else. */
function minimalConfig() {
	return {
		oauth: {
			jwt: {
				algorithm: "HS256",
				secret: "11".repeat(32),
				mode: "verify",
				issuer: "https://issuer.test",
				audience: "https://api.test",
			},
		},
		attribute: { collectors: [] },
		rule: { collectors: [] },
	};
}
