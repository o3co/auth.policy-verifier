// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The layer this suite pins, and why it is the odd one out.
 *
 * The other suites in this directory are deliberately ENGINE-agnostic: they take
 * an adapter that decides a request somehow, and say nothing about how the
 * request arrived. `decisionContract.mts` would be satisfied by an in-process
 * OPA, a Cedar adapter, or a function call — that is the point, because the
 * thing it pins is the migration seam *underneath* the endpoint.
 *
 * This one pins the seam ABOVE it: the HTTP surface itself. Status codes, the
 * exact key set of each response body, which refusal wins when a request is
 * wrong in two ways at once. `VerifierEndpoint` — the interface an enforcement
 * layer codes against — lives in o3co/protobuf.interceptors, so nothing in this
 * repository was checking that the wire shape it publishes is the wire shape
 * that repository implements (#125). An engine swap is invisible to a caller;
 * a field rename here breaks every caller at once, silently, at runtime.
 *
 * So the adapter here is a TRANSPORT, not an engine: it puts bytes on the wire
 * and reports the raw answer. An adapter for the OPA or Cedar deployment of
 * this same service satisfies this suite by answering identically over HTTP,
 * which is exactly the "drop-in replaceable behind `VerifierEndpoint`" claim
 * the README makes.
 *
 * **The fixtures are JSON files, not literals in this module** — see
 * `fixtures/wireContract/`. The enforcement layer is a different repository
 * (and need not be TypeScript); a table it can read is the only version of this
 * contract that can be shared rather than re-typed, and re-typing is the drift
 * #125 was filed about. This module is the runner; the contract is the data.
 *
 * **The table is the post-#118 contract.** #118 moved body validation ahead of
 * authentication and gave the body parser's own failures the deny envelope,
 * which changed six answers on the wire: three that were 401 and are now 400,
 * and three that were Express's HTML error page and are now this envelope. Those
 * rows carry `"issue": "#118"` and say so in their `pins`, so a reader who finds
 * this suite disagreeing with an older client knows which side moved and when.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/** Which decision endpoint a case is sent to. */
export type WireEndpoint = "/verify" | "/verify/batch";

/**
 * What the sender puts in the `Authorization` header. The adapter mints each
 * one, because what makes a token verifiable is the deployment's own key
 * material — the contract is what the endpoint does with each kind, not how it
 * is signed.
 */
export type WireCredential =
	/** A token this deployment verifies, carrying `fixtures.subject` as its `sub`. */
	| "valid"
	/** The same, but with no `sub` claim at all — the #158 case. */
	| "validWithoutSubject"
	/** No `Authorization` header. */
	| "none"
	/** A bearer token that will not verify. */
	| "unverifiable"
	/** A well-formed header naming a scheme that is not Bearer. */
	| "unsupportedScheme";

/**
 * What is sent as the body. `overBodyLimit` and `overBatchSize` are built by
 * the adapter rather than carried here: both are operator knobs, and the
 * contract is that the limit exists and how exceeding it is answered, not what
 * number this deployment set it to.
 */
export type WirePayload =
	| { kind: "json"; value: unknown }
	| { kind: "text"; text: string }
	| { kind: "overBodyLimit" }
	| { kind: "overBatchSize" };

/** One request, as the transport must send it. */
export interface WireExchange {
	endpoint: WireEndpoint;
	credential: WireCredential;
	/** Explicit `Content-Type`; omitted means `application/json`. */
	contentType?: string;
	/** Sent verbatim as the `x-request-id` request header (#200); omitted means no header. */
	requestId?: string;
	payload: WirePayload;
}

/** One row of `fixtures/wireContract/requestCases.json`. */
export interface WireRequestCase extends WireExchange {
	/** Stable identifier, so another repository can reference one row. */
	id: string;
	/** What this row exists to pin, in one sentence. */
	pins: string;
	/** The issue that decided it. */
	issue: string;
	expect: { status: number; code: string };
	/** Substrings the refusal must name — a field, or a batch index. */
	messageMentions?: string[];
	/** Substrings of the request that must not come back in the answer. */
	mustNotEcho?: string[];
	/** Whether this row's answer is the envelope the READMEs print verbatim. */
	matchesDocumentedExample?: boolean;
}

/** The raw HTTP answer, before any interpretation. */
export interface WireResponse {
	status: number;
	/** The `Content-Type` header as received; `undefined` when there is none. */
	contentType: string | undefined;
	/** The parsed body. */
	body: unknown;
	/** The body as bytes-as-text, for the assertions about what is *not* in it. */
	text: string;
	/** The `x-request-id` response header as received (#200); `undefined` when there is none. */
	requestId?: string;
}

/** A decision request body, as `POST /verify` takes it. */
export interface WireDecisionRequest {
	resource: string;
	action: string;
	context?: Record<string, unknown>;
}

/**
 * The requests this deployment's own policy answers a particular way. The suite
 * pins the wire shape and the relationships between its parts, never a
 * particular policy — so each of these is the deployment's to supply.
 */
export interface WireFixtures {
	/** The `sub` the `valid` credential carries. */
	subject: string;
	/** A request this policy allows. */
	allowed: WireDecisionRequest;
	/** A request this policy denies. */
	denied: WireDecisionRequest;
	/**
	 * Optional: a request that denies with at least one rule group still
	 * passing, so `satisfiedBy`'s "on a passing group only" half is checked
	 * against a response that carries both kinds of group at once (#135).
	 */
	partiallySatisfied?: WireDecisionRequest;
	/**
	 * Optional: a request whose collector fan-out runs out of time, for the
	 * `collector_timeout` deny (#115). A deployment with no stallable collector
	 * omits it and the two cases that need it do not run.
	 */
	stalling?: WireDecisionRequest;
	/**
	 * Optional: a request two attribute collectors answer with different scalar
	 * values for one key, for the `attribute_conflict` deny (#174, shipped in
	 * v0.4.0 and missing from this table until #182). Omitted by a deployment
	 * that cannot stage a conflict.
	 */
	conflicting?: WireDecisionRequest;
	/**
	 * Optional: a request whose collector fails outright — not a timeout — for
	 * the terminal `internal_error` envelope (#182). Omitted by a deployment
	 * with no failable collector.
	 */
	failing?: WireDecisionRequest;
	/**
	 * Optional (#244): requests decided with a rule that reports an evaluation,
	 * on a deployment whose responses include it (`verify.evaluationInResponse =
	 * "include"`). Omitted by a deployment that does not opt in or has no
	 * policy-backed rule — the cases that need it do not run, and every other
	 * case still holds its responses to the envelope, where `evaluation` is
	 * optional. `confirmed` is a request whose evaluator vouched for the revision
	 * it evaluated; the other two are for a deployment that can stage them.
	 */
	reportingEvaluation?: {
		confirmed: WireDecisionRequest;
		/** A request answered by an evaluator that does not say what it evaluated. */
		unconfirmed?: WireDecisionRequest;
		/** A request the rule denied before its evaluator was asked. */
		notInvoked?: WireDecisionRequest;
		/** A request whose evaluator completed and named the policies that determined it (#199). */
		determining?: WireDecisionRequest;
	};
}

/** Hooks a decision endpoint must provide to be checked against the wire contract. */
export interface WireContractAdapter {
	/** Deployment name, used in test titles. */
	name: string;
	/** Sends one exchange and reports the raw answer. Never throws on a 4xx. */
	send(exchange: WireExchange): Promise<WireResponse>;
	fixtures: WireFixtures;
}

/** The shape of `fixtures/wireContract/responseEnvelopes.json`. */
interface ResponseEnvelopes {
	error: { keys: string[]; decision: string; documentedExample: string };
	decision: {
		required: string[];
		optional: string[];
		denyAlsoCarries: string[];
		allowNeverCarries: string[];
	};
	batch: { keys: string[] };
	ruleGroup: { required: string[]; onlyOnAPassingGroup: string[] };
	ruleOutcome: { required: string[]; optional: string[] };
	evaluation: {
		statuses: string[];
		notInvoked: { keys: string[] };
		evaluated: {
			statuses: string[];
			required: string[];
			onlyWhenRevisionIsNull: string[];
			onlyWhenCompleted: string[];
		};
		determiningPolicies: {
			maxItems: number;
			idMaxLength: number;
			idLengthUnit: string;
			idWellFormed: boolean;
			idForbiddenRanges: [string, string][];
			omitted: { minimum: number; onlyBeside: string };
			about: string;
		};
		revision: { pattern: string; maxLength: number; about: string };
	};
	status: Record<string, number>;
	codes: Record<string, string>;
	requestId: {
		header: string;
		maxLength: number;
		pattern: string;
		echoedOn: string;
		otherwise: string;
	};
}

/**
 * Reads one fixture file.
 *
 * `readFileSync` rather than an `import ... with { type: "json" }`: these files
 * are a data table another repository consumes by path, and reading them as
 * data is what keeps that true. It also spares `tests/integration` a
 * `resolveJsonModule` setting whose only purpose would be to type a file the
 * interfaces above already describe.
 */
export function readWireContractFixture<T>(name: string): T {
	return JSON.parse(
		readFileSync(new URL(`./fixtures/wireContract/${name}`, import.meta.url), "utf8"),
	) as T;
}

/** The response envelopes, as data. Exported so a driver can assert against the same table. */
export const RESPONSE_ENVELOPES =
	readWireContractFixture<ResponseEnvelopes>("responseEnvelopes.json");

/** The refusal table, as data. */
export const REQUEST_CASES = readWireContractFixture<{ cases: WireRequestCase[] }>(
	"requestCases.json",
).cases;

/** Every key of `body`, sorted, for an exact-key-set comparison. */
const keysOf = (body: unknown): string[] => Object.keys(body as Record<string, unknown>).sort();

/** The batch envelope around a list of decision requests. */
const batchOf = (requests: WireDecisionRequest[]) => ({ decisions: requests });

/**
 * Conformance suite pinning the `VerifierEndpoint` wire contract
 * (o3co/auth.policy-verifier#125).
 *
 * See the header of this file for which layer this pins and why it is not
 * engine-agnostic like its neighbours.
 */
export function describeWireContractConformance(adapter: WireContractAdapter): void {
	const {
		error,
		decision: decisionEnvelope,
		batch,
		ruleGroup,
		ruleOutcome,
		evaluation: evaluationEnvelope,
		status,
		codes,
		requestId,
	} = RESPONSE_ENVELOPES;

	/** Sends a decision body with the given credential, defaulting to a usable one. */
	const post = (
		endpoint: WireEndpoint,
		value: unknown,
		credential: WireCredential = "valid",
	): Promise<WireResponse> =>
		adapter.send({ endpoint, credential, payload: { kind: "json", value } });

	/**
	 * Asserts one revision reference is the bounded `scheme:encoded` shape the
	 * contract carries (#244) — which is what keeps a path, a label or policy
	 * text from ever being one.
	 */
	const expectRevision = (value: unknown): void => {
		expect(typeof value).toBe("string");
		expect((value as string).length).toBeLessThanOrEqual(evaluationEnvelope.revision.maxLength);
		expect(value).toMatch(new RegExp(evaluationEnvelope.revision.pattern));
	};

	/**
	 * Asserts one outcome's `evaluation` is one of the three shapes the contract
	 * allows (#244), exhaustively: a status from the table; no revision key of
	 * either kind on an evaluator that was never invoked; otherwise a `revision`
	 * that is a reference or an explicit `null`, with `loadedRevision` beside it
	 * only in the `null` case — so the digest of a snapshot nobody confirmed can
	 * never sit under the name that claims it was evaluated.
	 */
	const expectEvaluation = (value: unknown): Record<string, unknown> => {
		expect(value).toBeTypeOf("object");
		expect(value).not.toBeNull();
		const evaluation = value as Record<string, unknown>;
		expect(evaluationEnvelope.statuses).toContain(evaluation.status);

		if (!evaluationEnvelope.evaluated.statuses.includes(evaluation.status as string)) {
			expect(keysOf(evaluation)).toEqual([...evaluationEnvelope.notInvoked.keys].sort());
			return evaluation;
		}
		for (const key of evaluationEnvelope.evaluated.required) {
			expect(Object.keys(evaluation)).toContain(key);
		}
		const permitted = new Set([
			...evaluationEnvelope.evaluated.required,
			...(evaluation.revision === null ? evaluationEnvelope.evaluated.onlyWhenRevisionIsNull : []),
			...(evaluation.status === "completed" ? evaluationEnvelope.evaluated.onlyWhenCompleted : []),
		]);
		expect(Object.keys(evaluation).filter((key) => !permitted.has(key))).toEqual([]);
		if (evaluation.revision !== null) expectRevision(evaluation.revision);
		for (const key of evaluationEnvelope.evaluated.onlyWhenRevisionIsNull) {
			if (key in evaluation) expectRevision(evaluation[key]);
		}
		if ("determiningPolicies" in evaluation) {
			expectDeterminingPolicies(evaluation.determiningPolicies);
		}
		if ("determiningPoliciesOmitted" in evaluation) {
			// A count of what the list could not carry, so never without the list.
			const { omitted } = evaluationEnvelope.determiningPolicies;
			expect(evaluation).toHaveProperty(omitted.onlyBeside);
			expect(Number.isSafeInteger(evaluation.determiningPoliciesOmitted)).toBe(true);
			expect(evaluation.determiningPoliciesOmitted as number).toBeGreaterThanOrEqual(
				omitted.minimum,
			);
		}
		return evaluation;
	};

	/**
	 * Asserts a completed evaluation's determining policies (#199) are the
	 * bounded set the contract carries: a list, no longer than `maxItems`, of
	 * distinct ids, each well-formed, 1 to `idMaxLength` UTF-16 units long, and
	 * free of every code point in `idForbiddenRanges` — which is what keeps an
	 * id from breaking a log line or displaying as another id.
	 */
	const expectDeterminingPolicies = (value: unknown): void => {
		const shape = evaluationEnvelope.determiningPolicies;
		const forbidden = shape.idForbiddenRanges.map(
			([low, high]) => [Number.parseInt(low, 16), Number.parseInt(high, 16)] as const,
		);
		expect(Array.isArray(value)).toBe(true);
		const ids = value as unknown[];
		expect(ids.length).toBeLessThanOrEqual(shape.maxItems);
		expect(new Set(ids).size).toBe(ids.length);
		for (const id of ids) {
			expect(typeof id).toBe("string");
			const text = id as string;
			expect(text.length).toBeGreaterThan(0);
			expect(text.length).toBeLessThanOrEqual(shape.idMaxLength);
			if (shape.idWellFormed) expect(text.isWellFormed()).toBe(true);
			const outside = [...text].filter((char) => {
				const code = char.codePointAt(0) as number;
				return forbidden.some(([low, high]) => code >= low && code <= high);
			});
			expect(outside).toEqual([]);
		}
	};

	/** Every `evaluation` a decision body carries, in evaluation order, each checked. */
	const evaluationsOf = (body: unknown): Record<string, unknown>[] =>
		(
			body as { reason: { groups: { evaluated: Record<string, unknown>[] }[] } }
		).reason.groups.flatMap((group) =>
			group.evaluated.flatMap((outcome) =>
				"evaluation" in outcome ? [expectEvaluation(outcome.evaluation)] : [],
			),
		);

	/**
	 * Asserts one decision body carries exactly the contract's keys, and that its
	 * `reason` is built the way the contract says.
	 */
	const expectDecisionEnvelope = (body: unknown): Record<string, unknown> => {
		const decision = body as Record<string, unknown>;
		const permitted = new Set([
			...decisionEnvelope.required,
			...decisionEnvelope.optional,
			...(decision.decision === "deny" ? decisionEnvelope.denyAlsoCarries : []),
		]);

		for (const key of decisionEnvelope.required) expect(Object.keys(decision)).toContain(key);
		// Exhaustive in both directions: a key the contract never promised is drift
		// as surely as a missing one, because a client that starts reading it has
		// coupled itself to something no version of this contract guarantees.
		expect(Object.keys(decision).filter((key) => !permitted.has(key))).toEqual([]);
		if (decision.decision === "deny") {
			for (const key of decisionEnvelope.denyAlsoCarries) {
				expect(Object.keys(decision)).toContain(key);
			}
		} else {
			for (const key of decisionEnvelope.allowNeverCarries) {
				expect(Object.keys(decision)).not.toContain(key);
			}
		}

		const groups = (decision.reason as { groups: Record<string, unknown>[] }).groups;
		expect(Array.isArray(groups)).toBe(true);
		for (const group of groups) {
			const permittedGroupKeys = new Set([...ruleGroup.required, ...ruleGroup.onlyOnAPassingGroup]);
			for (const key of ruleGroup.required) expect(Object.keys(group)).toContain(key);
			expect(Object.keys(group).filter((key) => !permittedGroupKeys.has(key))).toEqual([]);
			const permittedOutcomeKeys = new Set([...ruleOutcome.required, ...ruleOutcome.optional]);
			for (const outcome of group.evaluated as Record<string, unknown>[]) {
				for (const key of ruleOutcome.required) expect(Object.keys(outcome)).toContain(key);
				expect(Object.keys(outcome).filter((key) => !permittedOutcomeKeys.has(key))).toEqual([]);
				// #244: optional, and held to its own envelope wherever it appears.
				if ("evaluation" in outcome) expectEvaluation(outcome.evaluation);
			}
		}
		return decision;
	};

	describe(`wire contract conformance — ${adapter.name}`, () => {
		describe("every refusal is the deny envelope, and nothing else", () => {
			for (const wireCase of REQUEST_CASES) {
				it(`${wireCase.id} → ${wireCase.expect.status} ${wireCase.expect.code} (${wireCase.pins})`, async () => {
					const res = await adapter.send(wireCase);

					expect(res.status).toBe(wireCase.expect.status);
					// The whole point of the envelope: a client that parses only
					// decision JSON is never handed Express's HTML error page.
					expect(res.contentType).toMatch(/^application\/json/);

					const body = res.body as Record<string, unknown>;
					expect(keysOf(body)).toEqual([...error.keys].sort());
					expect(body.decision).toBe(error.decision);
					expect(body.code).toBe(wireCase.expect.code);
					expect(typeof body.message).toBe("string");
					expect(body.message).not.toBe("");

					for (const mention of wireCase.messageMentions ?? []) {
						expect(body.message).toContain(mention);
					}
					for (const secret of wireCase.mustNotEcho ?? []) {
						expect(res.text).not.toContain(secret);
					}
					if (wireCase.matchesDocumentedExample) {
						expect(body).toEqual(JSON.parse(error.documentedExample));
					}
				});
			}
		});

		describe("a decision", () => {
			it("answers 200 and the allow envelope for a request the policy allows", async () => {
				const res = await post("/verify", adapter.fixtures.allowed);

				expect(res.status).toBe(status.allow);
				const body = expectDecisionEnvelope(res.body);
				expect(body.decision).toBe("allow");
				expect(body.resource).toBe(adapter.fixtures.allowed.resource);
				expect(body.action).toBe(adapter.fixtures.allowed.action);
			});

			it("answers 403 and the deny envelope for a request the policy denies", async () => {
				// 403 rather than 200-with-a-deny: the status is the answer, so an
				// enforcement layer that only ever reads it still fails closed.
				const res = await post("/verify", adapter.fixtures.denied);

				expect(res.status).toBe(status.deny);
				const body = expectDecisionEnvelope(res.body);
				expect(body.decision).toBe("deny");
				expect(body.resource).toBe(adapter.fixtures.denied.resource);
				expect(body.action).toBe(adapter.fixtures.denied.action);
			});

			it("names the token's subject, and never one the body could have carried", async () => {
				const res = await post("/verify", adapter.fixtures.allowed);
				expect((res.body as Record<string, unknown>).subject).toBe(adapter.fixtures.subject);
			});

			it("omits subject entirely when the token carries no sub (#158)", async () => {
				// Omitted, not `null` and not `""`: a subject that does not exist must
				// not be reported as one every subject-less token shares.
				const res = await post("/verify", adapter.fixtures.allowed, "validWithoutSubject");

				expect([status.allow, status.deny]).toContain(res.status);
				expect(Object.keys(res.body as Record<string, unknown>)).not.toContain("subject");
				expectDecisionEnvelope(res.body);
			});

			it("takes its deny code from the first failing group's first rule", async () => {
				const res = await post("/verify", adapter.fixtures.denied);
				const body = res.body as Record<string, unknown>;
				const groups = (body.reason as { groups: { passed: boolean; evaluated: unknown[] }[] })
					.groups;
				const firstFailing = groups.find((group) => !group.passed);

				expect(firstFailing).toBeDefined();
				const representative = firstFailing?.evaluated[0] as Record<string, unknown>;
				expect(body.code).toBe(representative.code);
				expect(body.message).toBe(representative.message);
			});

			it("names what decided each passing group, and nothing on a failing one (#135)", async () => {
				const request = adapter.fixtures.partiallySatisfied ?? adapter.fixtures.denied;
				const res = await post("/verify", request);
				const groups = (
					res.body as {
						reason: {
							groups: {
								passed: boolean;
								evaluated: Record<string, unknown>[];
								satisfiedBy?: Record<string, unknown>;
							}[];
						};
					}
				).reason.groups;

				expect(groups.length).toBeGreaterThan(0);
				for (const group of groups) {
					expect(group.evaluated.length).toBeGreaterThan(0);
					if (group.passed) {
						expect(group.satisfiedBy).toEqual(group.evaluated.at(-1));
						expect(group.satisfiedBy?.passed).toBe(true);
					} else {
						expect(group.satisfiedBy).toBeUndefined();
						expect(group.evaluated.every((outcome) => outcome.passed === false)).toBe(true);
					}
				}
			});
		});

		describe("a batch", () => {
			it("answers 200 with one decision per entry, in request order", async () => {
				const requests = [
					adapter.fixtures.allowed,
					adapter.fixtures.denied,
					adapter.fixtures.allowed,
				];
				const res = await post("/verify/batch", batchOf(requests));

				expect(res.status).toBe(status.batchDecided);
				const body = res.body as { decisions: Record<string, unknown>[] };
				expect(keysOf(body)).toEqual([...batch.keys].sort());
				expect(body.decisions).toHaveLength(requests.length);
				expect(body.decisions.map((d) => [d.resource, d.action])).toEqual(
					requests.map((r) => [r.resource, r.action]),
				);
				// Each entry is the same envelope a single decision answers with —
				// which is what makes the batch a round-trip optimization rather than
				// a second response format to implement against.
				for (const entry of body.decisions) expectDecisionEnvelope(entry);
			});

			it("answers 200 even when every entry denies — the status reports that it decided", async () => {
				const res = await post(
					"/verify/batch",
					batchOf([adapter.fixtures.denied, adapter.fixtures.denied]),
				);

				expect(res.status).toBe(status.batchDecided);
				const body = res.body as { decisions: Record<string, unknown>[] };
				expect(body.decisions.map((entry) => entry.decision)).toEqual(["deny", "deny"]);
			});

			it.runIf(adapter.fixtures.stalling)(
				"refuses a batch on one bad entry before deciding any of the others",
				async () => {
					// The observable form of "validated whole, then decided": the first
					// entry would take the collector budget and answer 403
					// collector_timeout, so a 400 naming index 1 is only possible if no
					// entry was decided at all.
					const stalling = adapter.fixtures.stalling;
					if (!stalling) return;
					const res = await post(
						"/verify/batch",
						batchOf([stalling, { resource: "  ", action: "read" }]),
					);

					expect(res.status).toBe(status.invalidRequest);
					const body = res.body as Record<string, unknown>;
					expect(body.code).toBe(codes.invalidRequest);
					expect(body.message).toContain("decisions[1]");
				},
			);
		});

		describe("a collector fan-out that runs out of time (#115)", () => {
			it.runIf(adapter.fixtures.stalling)("denies with 403 and an empty reason", async () => {
				const stalling = adapter.fixtures.stalling;
				if (!stalling) return;
				const res = await post("/verify", stalling);

				// A deny and specifically not a 5xx: what the verifier can stand
				// behind is "not established", and the safe rendering of that is a
				// refusal an enforcement layer will not retry or fall back around.
				expect(res.status).toBe(status.deny);
				const body = expectDecisionEnvelope(res.body);
				expect(body.decision).toBe("deny");
				expect(body.code).toBe(codes.collectorTimeout);
				// No group ran, and the reason says so rather than inventing one.
				expect(body.reason).toEqual({ groups: [] });
				// The message reaches the caller, so it names no collector and no bound.
				expect(body.message).not.toMatch(/collector|ms\b/i);
			});

			it.runIf(adapter.fixtures.stalling)(
				"denies only the entry that stalled, and decides the rest",
				async () => {
					const stalling = adapter.fixtures.stalling;
					if (!stalling) return;
					const res = await post(
						"/verify/batch",
						batchOf([adapter.fixtures.allowed, stalling, adapter.fixtures.allowed]),
					);

					expect(res.status).toBe(status.batchDecided);
					const body = res.body as { decisions: Record<string, unknown>[] };
					expect(body.decisions.map((entry) => entry.decision)).toEqual(["allow", "deny", "allow"]);
					expect(body.decisions[1].code).toBe(codes.collectorTimeout);
				},
			);
		});

		// #182: three codes a deployed instance can legally answer were missing
		// from the table, so the contract an enforcement layer reads was narrower
		// than the surface it meets. Two are exercised on the wire below; the
		// third — the optional caller-auth gate's — cannot be, and the case says
		// why.
		describe("a scalar attribute conflict (#174, table row #182)", () => {
			it.runIf(adapter.fixtures.conflicting)("denies with 403 and an empty reason", async () => {
				const conflicting = adapter.fixtures.conflicting;
				if (!conflicting) return;
				const res = await post("/verify", conflicting);

				// The same rendering as collector_timeout, for the same reason:
				// two collectors disagreeing about one attribute means the
				// decision's inputs are not established, and the safe answer is a
				// deny an enforcement layer will not retry around.
				expect(res.status).toBe(status.deny);
				const body = expectDecisionEnvelope(res.body);
				expect(body.decision).toBe("deny");
				expect(body.code).toBe(codes.attributeConflict);
				// No rule group was evaluated, and the reason says so.
				expect(body.reason).toEqual({ groups: [] });
			});
		});

		describe("a collector failure that is not a timeout (table row #182)", () => {
			it.runIf(adapter.fixtures.failing)("answers the terminal 500 envelope", async () => {
				const failing = adapter.fixtures.failing;
				if (!failing) return;
				const res = await post("/verify", failing);

				// A genuine fault, not a refusal the verifier can stand behind —
				// the one answer in this table that IS a 5xx, and it still wears
				// the deny envelope so a client that parses only decision JSON
				// reads it as the deny it must treat it as.
				expect(res.status).toBe(status.internalError);
				expect(keysOf(res.body)).toEqual([...error.keys].sort());
				const body = res.body as { decision: string; code: string };
				expect(body.decision).toBe(error.decision);
				expect(body.code).toBe(codes.internalError);
			});
		});

		describe("the caller's request id (#200)", () => {
			/** An id inside the contract's shape: the one protobuf.interceptors mints. */
			const ID = "20260917123456_0123456789abcdef";

			/** Sends a JSON body with a request id and a usable credential. */
			const postWithId = (
				endpoint: WireEndpoint,
				value: unknown,
				id: string,
				credential: WireCredential = "valid",
			): Promise<WireResponse> =>
				adapter.send({ endpoint, credential, requestId: id, payload: { kind: "json", value } });

			it("states a shape the example id is inside of", () => {
				// The table is data another repository reads; this pins that its
				// pattern and bound describe an id a caller can actually send.
				expect(requestId.header).toBe("x-request-id");
				expect(ID.length).toBeLessThanOrEqual(requestId.maxLength);
				expect(new RegExp(requestId.pattern).test(ID)).toBe(true);
			});

			it("echoes the id on an allow, a deny, a batch and a refusal alike", async () => {
				const answers = [
					await postWithId("/verify", adapter.fixtures.allowed, ID),
					await postWithId("/verify", adapter.fixtures.denied, ID),
					await postWithId("/verify/batch", batchOf([adapter.fixtures.allowed]), ID),
					await postWithId("/verify", adapter.fixtures.allowed, ID, "none"),
					await postWithId("/verify", [], ID),
				];

				expect(answers.map((res) => res.status)).toEqual([
					status.allow,
					status.deny,
					status.batchDecided,
					status.unauthenticated,
					status.invalidRequest,
				]);
				for (const res of answers) expect(res.requestId).toBe(ID);
			});

			it.runIf(adapter.fixtures.failing)("echoes the id on the terminal 500 too", async () => {
				const failing = adapter.fixtures.failing;
				if (!failing) return;
				const res = await postWithId("/verify", failing, ID);

				expect(res.status).toBe(status.internalError);
				expect(res.requestId).toBe(ID);
			});

			it("mints none: a request without an id is answered without one", async () => {
				const res = await post("/verify", adapter.fixtures.allowed);

				expect(res.status).toBe(status.allow);
				expect(res.requestId).toBeUndefined();
			});

			it.each([
				["over the length bound", "r".repeat(requestId.maxLength + 1)],
				["outside the pattern", "req 1"],
			])("echoes no id %s", async (_what, id) => {
				expect(id.length <= requestId.maxLength && new RegExp(requestId.pattern).test(id)).toBe(
					false,
				);
				const res = await postWithId("/verify", adapter.fixtures.allowed, id);

				// Still decided: an unusable id is absent, not a refusal.
				expect(res.status).toBe(status.allow);
				expect(res.requestId).toBeUndefined();
			});
		});

		describe("the evaluation behind a rule's answer (#244)", () => {
			const reporting = adapter.fixtures.reportingEvaluation;

			it.runIf(reporting)(
				"names the revision the evaluator vouched for, under revision",
				async () => {
					const res = await post("/verify", reporting?.confirmed);
					const evaluations = evaluationsOf(expectDecisionEnvelope(res.body));
					// A string, and not merely "not null": a `not_invoked` evaluation has
					// no `revision` key at all, and `undefined !== null`. A response may
					// well carry one beside the confirmed one — an OR alternative that
					// never reached its evaluator, then the one that did.
					const vouched = evaluations.filter(
						(evaluation) => typeof evaluation.revision === "string",
					);
					expect(vouched.length).toBeGreaterThan(0);
					for (const evaluation of vouched) {
						expect(evaluationEnvelope.evaluated.statuses).toContain(evaluation.status);
						expect(evaluation).not.toHaveProperty("loadedRevision");
					}
				},
			);

			it.runIf(reporting?.unconfirmed)(
				"says null when what was evaluated is not established, and what was loaded beside it",
				async () => {
					const res = await post("/verify", reporting?.unconfirmed);
					const evaluations = evaluationsOf(expectDecisionEnvelope(res.body));
					const unconfirmed = evaluations.filter((evaluation) => evaluation.revision === null);
					expect(unconfirmed.length).toBeGreaterThan(0);
					// The envelope check above already held `loadedRevision`, where
					// present, to the revision shape — and refused it anywhere else.
				},
			);

			it.runIf(reporting?.determining)(
				"names the policies that determined a completed answer, and only on a completed one (#199)",
				async () => {
					const res = await post("/verify", reporting?.determining);
					const evaluations = evaluationsOf(expectDecisionEnvelope(res.body));
					const naming = evaluations.filter((evaluation) => "determiningPolicies" in evaluation);
					expect(naming.length).toBeGreaterThan(0);
					for (const evaluation of naming) {
						expect(evaluation.status).toBe("completed");
					}
				},
			);

			it.runIf(reporting?.notInvoked)(
				"claims no revision of either kind for an evaluator that was never invoked",
				async () => {
					const res = await post("/verify", reporting?.notInvoked);
					const evaluations = evaluationsOf(expectDecisionEnvelope(res.body));
					const notInvoked = evaluations.filter(
						(evaluation) => evaluation.status === "not_invoked",
					);
					expect(notInvoked.length).toBeGreaterThan(0);
					for (const evaluation of notInvoked) {
						expect(keysOf(evaluation)).toEqual([...evaluationEnvelope.notInvoked.keys].sort());
					}
				},
			);

			it.runIf(reporting?.unconfirmed && reporting?.notInvoked)(
				"attributes each batch entry to its own evaluation, in request order",
				async () => {
					const requests = [reporting?.notInvoked, reporting?.confirmed, reporting?.unconfirmed];
					const singly = [];
					for (const request of requests) {
						singly.push(evaluationsOf((await post("/verify", request)).body));
					}
					const res = await post("/verify/batch", { decisions: requests });
					expect(res.status).toBe(status.batchDecided);
					const batched = (res.body as { decisions: unknown[] }).decisions.map((entry) =>
						evaluationsOf(expectDecisionEnvelope(entry)),
					);
					// Not whichever evaluation came last, stamped on all three.
					expect(batched).toEqual(singly);
					expect(new Set(batched.map((entry) => JSON.stringify(entry))).size).toBe(requests.length);
				},
			);

			it.runIf(adapter.fixtures.stalling)(
				"carries none on a deny the router made itself — no policy decided it",
				async () => {
					const res = await post("/verify", adapter.fixtures.stalling);
					expect(evaluationsOf(expectDecisionEnvelope(res.body))).toEqual([]);
				},
			);
		});

		describe("the code the table names without a request case (#182)", () => {
			it("names the caller-auth gate's refusal, which answers ahead of this surface (#108)", () => {
				// The optional `http.callerAuth` gate sits IN FRONT of the pinned
				// surface — it answers before the body is parsed, so it is not one
				// of the per-request refusals the request cases enumerate, and this
				// reference deployment does not mount it. The table still names it:
				// an enforcement layer switching on `code` meets it wherever a
				// deployment sets the gate, and a vocabulary documented as
				// exhaustive must not be narrower than the wire.
				expect(codes.callerUnauthenticated).toBe("caller_unauthenticated");
				expect(status.callerUnauthenticated).toBe(401);
			});
		});
	});
}
