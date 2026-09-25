// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The reference deployment the wire contract is checked against: this
 * repository's own `createVerifyRouter`, over real HTTP.
 *
 * Everything the suite needs that is deployment-specific is here — the key
 * material, the policy that makes one request an allow and another a deny, and
 * the collector that can be made to stall. The contract itself is in
 * `conformance/fixtures/wireContract/*.json`, which is what another repository
 * implementing `VerifierEndpoint` reads.
 */

import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	RequestContextAttributeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
	Rule,
	RuleCollector,
	RuleEvaluation,
} from "@o3co/auth.policy-verifier.core";
import {
	AttributePipeline,
	consoleLogger,
	DETERMINING_POLICIES_MAX,
	evaluate,
	isReportablePolicyId,
	POLICY_ID_FORBIDDEN_RANGES,
	POLICY_ID_MAX_LENGTH,
	POLICY_REVISION_MAX_LENGTH,
	POLICY_REVISION_PATTERN,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import {
	createTokenAuthenticator,
	createVerifyRouter,
	type VerifyRouterConfig,
} from "@o3co/auth.policy-verifier.server";
import express from "express";
import { SignJWT } from "jose";
import type { Test } from "supertest";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
	describeWireContractConformance,
	RESPONSE_ENVELOPES,
	type WireContractAdapter,
	type WireCredential,
	type WireExchange,
	type WirePayload,
	type WireResponse,
} from "./conformance/wireContract.mjs";

const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";
const SUBJECT = "user-1";
const secret = new TextEncoder().encode("wire-contract-conformance-secret");

/** The action the stalling collector below never answers for. */
const STALLING_ACTION = "stall";

/** The action that makes two collectors disagree about `tenantId` (#174). */
const CONFLICTING_ACTION = "conflict";

/** The action the failing collector below throws on — a fault, not a timeout. */
const FAILING_ACTION = "explode";

/**
 * The actions the policy-backed rule below reports each evaluation shape for
 * (#244). `read` and `delete` — the suite's ordinary allow and deny — report a
 * completed evaluation of a vouched revision.
 */
const UNCONFIRMED_ACTION = "read-remote";
const NOT_INVOKED_ACTION = "read-unbuilt";

/**
 * Small enough that a case can exceed them cheaply, and stated here rather than
 * defaulted so the 413 and the batch-cap cases do not depend on this package's
 * default ever staying what it is. The contract is that a limit exists and how
 * it answers, not what number a deployment chose.
 */
const MAX_BODY_BYTES = 4096;
const MAX_BATCH_SIZE = 8;

/**
 * Answers instantly for every action but one, and never for that one — so a
 * single deployment serves both the ordinary cases and the `collector_timeout`
 * deny (#115) without a second app.
 */
const stallableCollector: AttributeCollector = {
	collect: (collectorContext: CollectorContext) =>
		collectorContext.action === STALLING_ACTION
			? new Promise<Attributes>(() => {})
			: Promise.resolve(new Map<string, unknown>()),
};

/**
 * For `CONFLICTING_ACTION`, answers `tenantId` with a value the request's own
 * `tenant_id` context never carries — so it and
 * `RequestContextAttributeCollector` disagree about one scalar, which is the
 * `attribute_conflict` deny (#174). Inert for every other action.
 */
const conflictableCollector: AttributeCollector = {
	collect: (collectorContext: CollectorContext) =>
		Promise.resolve(
			collectorContext.action === CONFLICTING_ACTION
				? new Map<string, unknown>([["tenantId", "a-tenant-no-request-names"]])
				: new Map<string, unknown>(),
		),
};

/**
 * For `FAILING_ACTION`, rejects with a plain error — the store-outage shape,
 * which is a genuine fault and must surface as the terminal `internal_error`
 * envelope rather than as any refusal (#182). Inert for every other action.
 */
const failableCollector: AttributeCollector = {
	collect: (collectorContext: CollectorContext) =>
		collectorContext.action === FAILING_ACTION
			? Promise.reject(new Error("wire-contract synthetic collector fault"))
			: Promise.resolve(new Map<string, unknown>()),
};

/**
 * A second rule group, driven by a request-context attribute, so a deny can
 * carry a passing group beside a failing one — which is what the `satisfiedBy`
 * case (#135) needs to see in one response.
 */
const tenantRuleCollector: RuleCollector = {
	async collect() {
		const rule: Rule = {
			ruleType: "tenant",
			code: "wrong_tenant",
			message: "Request is not for the acme tenant",
			verify: (attrs: Attributes) => attrs.get("tenantId") === "acme",
		};
		return [rule];
	},
};

/**
 * A rule group backed by a policy evaluator, as `packages/cedar` builds one:
 * each rule answers a boolean and reports, to the reporter core hands it for
 * that one call, how the evaluation went and which policy revision it
 * concerned (#244). Synthetic so that one deployment can stage every shape of
 * the evaluation envelope; the real collector's reports are pinned against
 * Cedar in `packages/cedar-wasm`.
 *
 * The group is an OR of two policy sources. For the ordinary actions the first
 * never reaches its evaluator and refuses, and the second evaluates and
 * passes — so one response carries a `not_invoked` outcome beside a confirmed
 * one, which is the shape a suite filtering on `revision !== null` mistook for
 * a confirmed evaluation (`undefined !== null`). It passes whatever it is
 * asked about except where a staged shape implies a denial, so the scope and
 * tenant groups beside it keep deciding the cases they always decided.
 */
const REVISION = `sha256:${"0123456789abcdef".repeat(4)}`;
const policyBackedRuleCollector: RuleCollector = {
	async collect(collectorContext: CollectorContext) {
		const reports = (passed: boolean, evaluation: RuleEvaluation): Rule => ({
			ruleType: "policy",
			code: "policy_deny",
			message: "Denied by policy",
			verify: (_attrs, report) => {
				report?.(evaluation);
				return passed;
			},
		});
		const unbuilt = reports(false, { status: "not_invoked" });
		switch (collectorContext.action) {
			case NOT_INVOKED_ACTION:
				return [unbuilt];
			case UNCONFIRMED_ACTION:
				return [reports(true, { status: "completed", revision: null, loadedRevision: REVISION })];
			default:
				return [
					unbuilt,
					reports(true, {
						status: "completed",
						revision: REVISION,
						determiningPolicies: ["10-permit-read"],
					}),
				];
		}
	},
};

/** The reference deployment, with whatever a second one needs to differ in. */
function deployment(
	overrides: Partial<VerifyRouterConfig> = {},
	ruleCollectors: RuleCollector[] = [],
): express.Express {
	const app = express();
	app.use(
		createVerifyRouter({
			...referenceConfig(ruleCollectors),
			...overrides,
		}),
	);
	return app;
}

function referenceConfig(ruleCollectors: RuleCollector[]): VerifyRouterConfig {
	return {
		authenticator: createTokenAuthenticator(
			{
				validate: true,
				key: secret,
				algorithms: ["HS256"],
				issuer: ISSUER,
				audience: AUDIENCE,
				tokenType: "at+jwt",
			},
			consoleLogger,
		),
		resourceParser: new DotNotationResourceParser(),
		attributePipeline: new AttributePipeline(
			[
				new PayloadScopeCollector(),
				new RequestContextAttributeCollector({
					attributes: [{ from: "tenant_id", to: "tenantId" }],
				}),
				stallableCollector,
				conflictableCollector,
				failableCollector,
			],
			// Bounds low enough that the stall is answered well inside vitest's own
			// timeout, and high enough that the in-memory collectors beside it are
			// never the thing that trips them.
			{ collectorTimeoutMs: 50, deadlineMs: 150 },
		),
		rulePipeline: new RulePipeline([
			new ResourceActionScopeRuleCollector(),
			tenantRuleCollector,
			...ruleCollectors,
		]),
		maxBodyBytes: MAX_BODY_BYTES,
		maxBatchSize: MAX_BATCH_SIZE,
	};
}

/** A token this deployment verifies, with or without a `sub` claim. */
async function mintToken(subject: string | undefined): Promise<string> {
	const jwt = new SignJWT({ scope: "read:project" })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		// Required since #110; the time claims are not what this suite is about,
		// so the token simply carries valid ones.
		.setExpirationTime("1h")
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE);
	return (subject === undefined ? jwt : jwt.setSubject(subject)).sign(secret);
}

/** The `Authorization` header each credential kind puts on the wire. */
async function authorization(credential: WireCredential): Promise<string | undefined> {
	switch (credential) {
		case "valid":
			return `Bearer ${await mintToken(SUBJECT)}`;
		case "validWithoutSubject":
			return `Bearer ${await mintToken(undefined)}`;
		case "unverifiable":
			return "Bearer not.a.token";
		case "unsupportedScheme":
			return "Basic dXNlcjpwYXNzd29yZA==";
		case "none":
			return undefined;
	}
}

const allowed = { resource: "project:1", action: "read", context: { tenant_id: "acme" } };

/** The body text each payload kind puts on the wire, already serialized. */
function serialize(payload: WirePayload): string {
	switch (payload.kind) {
		case "json":
			return JSON.stringify(payload.value);
		case "text":
			return payload.text;
		case "overBodyLimit":
			// One character past the limit is enough, and the padding rides in
			// `context` so the body is otherwise a request this policy would decide.
			return JSON.stringify({ ...allowed, context: { blob: "x".repeat(MAX_BODY_BYTES) } });
		case "overBatchSize":
			return JSON.stringify({
				decisions: Array.from({ length: MAX_BATCH_SIZE + 1 }, () => allowed),
			});
	}
}

const adapterFor = (
	name: string,
	app: express.Express,
	fixtures: Partial<WireContractAdapter["fixtures"]> = {},
): WireContractAdapter => ({
	name,

	async send(exchange: WireExchange): Promise<WireResponse> {
		let pending: Test = request(app).post(exchange.endpoint);
		const header = await authorization(exchange.credential);
		if (header !== undefined) pending = pending.set("Authorization", header);
		if (exchange.requestId !== undefined) pending = pending.set("x-request-id", exchange.requestId);

		// Always explicit: superagent's default for a string body is
		// form-urlencoded, and a case that means to send JSON must not depend on
		// which overload of `send` it happened to reach.
		const res = await pending
			.set("Content-Type", exchange.contentType ?? "application/json")
			.send(serialize(exchange.payload));

		return {
			status: res.status,
			contentType: res.headers["content-type"] as string | undefined,
			body: res.body,
			text: res.text,
			requestId: res.headers["x-request-id"] as string | undefined,
		};
	},

	fixtures: {
		subject: SUBJECT,
		allowed,
		// `delete:project` is a scope no token here carries, so the scope group
		// fails while the tenant group passes.
		denied: { resource: "project:1", action: "delete", context: { tenant_id: "acme" } },
		// The mirror image: the scope group passes and the tenant group does not,
		// so one response carries a `satisfiedBy` and an absence of one.
		partiallySatisfied: { resource: "project:1", action: "read", context: { tenant_id: "other" } },
		stalling: { resource: "project:1", action: STALLING_ACTION, context: { tenant_id: "acme" } },
		// `tenant_id` here and the collector's own answer disagree on `tenantId`.
		conflicting: {
			resource: "project:1",
			action: CONFLICTING_ACTION,
			context: { tenant_id: "acme" },
		},
		failing: { resource: "project:1", action: FAILING_ACTION, context: { tenant_id: "acme" } },
		...fixtures,
	},
});

// The deployment as it ships: `verify.evaluationInResponse` left at "omit". It
// runs the policy-backed group too, so that what the suite holds to the
// three-key outcome is a response that had an evaluation to leave out.
describeWireContractConformance(
	adapterFor(
		"@o3co/auth.policy-verifier.server createVerifyRouter over HTTP",
		deployment({}, [policyBackedRuleCollector]),
	),
);

// …and the same one opted in (#244), with a policy-backed rule group beside the
// others. The whole table runs again, because the opt-in must change nothing
// but the one optional key: every refusal, status and envelope is the same.
// The token carries `read:project` only, so the staged actions are told apart
// by the policy-backed rule and allowed by no scope — which is fine, the
// evaluation rides on the outcome whether the decision is an allow or a deny.
describeWireContractConformance(
	adapterFor(
		"@o3co/auth.policy-verifier.server with verify.evaluationInResponse = include",
		deployment({ evaluationInResponse: "include" }, [policyBackedRuleCollector]),
		{
			reportingEvaluation: {
				confirmed: allowed,
				determining: allowed,
				unconfirmed: {
					resource: "project:1",
					action: UNCONFIRMED_ACTION,
					context: { tenant_id: "acme" },
				},
				notInvoked: {
					resource: "project:1",
					action: NOT_INVOKED_ACTION,
					context: { tenant_id: "acme" },
				},
			},
		},
	),
);

/*
 * The fixture states the revision grammar, its length bound and the statuses
 * as data, for a driver that cannot import core. They are copies, and a copy
 * drifts: core would start refusing — or accepting — what the table still
 * says, and the suite would hold deployments to the stale half. Pinned here,
 * where both can be seen.
 */
describe("the fixture's evaluation table is core's own", () => {
	const { evaluation } = RESPONSE_ENVELOPES;

	it("states the revision grammar and bound core enforces", () => {
		expect(evaluation.revision.pattern).toBe(POLICY_REVISION_PATTERN.source);
		expect(evaluation.revision.maxLength).toBe(POLICY_REVISION_MAX_LENGTH);
	});

	it("states the determining-policy bounds and id shape core enforces (#199)", () => {
		expect(evaluation.determiningPolicies.maxItems).toBe(DETERMINING_POLICIES_MAX);
		expect(evaluation.determiningPolicies.idMaxLength).toBe(POLICY_ID_MAX_LENGTH);
		// The unit is what core counts in: an id of astral characters at the bound
		// holds half as many code points, and one unit more is refused.
		expect(evaluation.determiningPolicies.idLengthUnit).toBe("UTF-16 code units");
		const astral = "\u{1f600}".repeat(POLICY_ID_MAX_LENGTH / 2);
		expect(isReportablePolicyId(astral)).toBe(true);
		expect(isReportablePolicyId(`${astral}x`)).toBe(false);
		expect(
			evaluation.determiningPolicies.idForbiddenRanges.map(([low, high]) => [
				Number.parseInt(low, 16),
				Number.parseInt(high, 16),
			]),
		).toEqual(POLICY_ID_FORBIDDEN_RANGES.map(([low, high]) => [low, high]));
	});

	it("names as completed-only exactly the keys core takes on a completed report and refuses on a failed one (#199)", async () => {
		const accepts = async (report: Record<string, unknown>): Promise<boolean> =>
			evaluate(new Map(), [
				{
					ruleType: "policy",
					code: "policy_deny",
					message: "Denied by policy",
					verify: (_attrs, tell) => {
						tell?.(report as RuleEvaluation);
						return false;
					},
				},
			]).then(
				() => true,
				() => false,
			);
		const keys: Record<string, unknown> = {
			determiningPolicies: ["10-permit"],
			determiningPoliciesOmitted: 2,
		};
		for (const key of evaluation.evaluated.onlyWhenCompleted) {
			const pair =
				key === "determiningPoliciesOmitted"
					? { determiningPolicies: [], determiningPoliciesOmitted: keys[key] }
					: { [key]: keys[key] };
			expect(await accepts({ status: "completed", revision: null, ...pair })).toBe(true);
			expect(await accepts({ status: "failed", revision: null, ...pair })).toBe(false);
		}
		expect([...evaluation.evaluated.onlyWhenCompleted].sort()).toEqual(Object.keys(keys).sort());
	});

	it("states the omitted count's rules and id well-formedness as core holds them (#199)", async () => {
		const accepts = async (report: Record<string, unknown>): Promise<boolean> =>
			evaluate(new Map(), [
				{
					ruleType: "policy",
					code: "policy_deny",
					message: "Denied by policy",
					verify: (_attrs, tell) => {
						tell?.(report as RuleEvaluation);
						return false;
					},
				},
			]).then(
				() => true,
				() => false,
			);
		const { omitted, idWellFormed } = evaluation.determiningPolicies;
		const completed = { status: "completed", revision: null };
		const list = { [omitted.onlyBeside]: [] };
		expect(
			await accepts({ ...completed, ...list, determiningPoliciesOmitted: omitted.minimum }),
		).toBe(true);
		expect(
			await accepts({ ...completed, ...list, determiningPoliciesOmitted: omitted.minimum - 1 }),
		).toBe(false);
		expect(await accepts({ ...completed, determiningPoliciesOmitted: omitted.minimum })).toBe(
			false,
		);
		// Core refuses a lone surrogate, so the fixture must say ids are well-formed.
		expect(idWellFormed).toBe(true);
		expect(await accepts({ ...completed, determiningPolicies: ["a\ud800"] })).toBe(false);
	});

	it("lists exactly the statuses core accepts", async () => {
		const accepts = async (status: string): Promise<boolean> => {
			const report = status === "not_invoked" ? { status } : { status, revision: null };
			return evaluate(new Map(), [
				{
					ruleType: "policy",
					code: "policy_deny",
					message: "Denied by policy",
					verify: (_attrs, tell) => {
						tell?.(report as RuleEvaluation);
						return false;
					},
				},
			]).then(
				() => true,
				() => false,
			);
		};
		for (const status of evaluation.statuses) expect(await accepts(status)).toBe(true);
		expect(await accepts("skipped")).toBe(false);
		expect([...evaluation.evaluated.statuses, "not_invoked"].sort()).toEqual(
			[...evaluation.statuses].sort(),
		);
	});
});
