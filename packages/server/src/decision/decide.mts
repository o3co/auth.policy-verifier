// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * One decision (#251).
 *
 * What `POST /verify` runs once and `POST /verify/batch` runs per entry, with
 * nothing of the transport in it: the two collects, the evaluation, the sorting
 * of a failure into a deny the caller gets or a fault the route answers, the
 * `decision` line and the counters. The router owns everything on either side —
 * wire validation, caller and subject authentication, turning the caller's
 * disconnect into a signal, status codes and headers — and the one line a fault
 * produces, because a fault speaks for the request: a batch's 500 is one line
 * for the whole batch (#200).
 *
 * That split of the observability is the one the router always had, and it is
 * what keeps "one decision, one line, one count" simple for both routes. A
 * decision that was *made* — allow, deny, or one of the three denies a failure
 * is answered with — is reported here, once, at the moment it is made. A
 * decision that could not be made throws a {@link DecisionFault}, reports
 * nothing, and the route reports the fault once per request.
 */

import {
	type AttributePipeline,
	type Decision,
	type DecisionReason,
	type EvaluateOptions,
	type EventLogger,
	evaluate,
	FailureRecord,
	markUntrustedRequestContext,
	type Resource,
	type RulePipeline,
	type SubjectAttributes,
} from "@o3co/auth.policy-verifier.core";
import { DECISION_EVENT, decisionEvent, present } from "../observability/decisionEvent.mjs";
import {
	type ClassifiedFailure,
	classifyFailure,
	correlation,
	countCollectorFailure,
	type FailureCategory,
	loggableError,
} from "../observability/failure.mjs";
// Type only, on purpose: `metrics.mts` loads express and prom-client, and the
// decision reaches neither — `__tests__/dependencies.test.mts` holds that.
import type { DecisionMetrics } from "../observability/metrics.mjs";

/**
 * One decision the caller is asking for. The subject is deliberately absent:
 * it comes from the verified token, never from the body — accepting one here
 * would let any token holder ask for a decision about somebody else.
 */
export interface DecisionRequest {
	resource: string;
	action: string;
	context?: Record<string, unknown>;
}

/**
 * What the endpoint decided, and for whom.
 *
 * The four inputs an engine needs — subject, resource, action, context — are
 * named explicitly, and the outcome carries a structured `reason` rather than a
 * bare allow/deny. That is what lets a heavy-class engine (OPA's
 * `input document → decision`, OpenFGA's `check(user, relation, object)`, Cedar)
 * sit behind this same contract: the request carries enough for each of them to
 * form its own query, and the response has somewhere to put what decided.
 */
export interface DecisionResponse {
	/**
	 * JWT `sub` of the token presented. Absent when the token carries none — and
	 * an empty `sub` counts as none, the disposition the audit line takes for the
	 * same value (#158). `subject: ""` would name a subject that does not exist,
	 * and every token without one would name the same one.
	 */
	subject?: string;
	resource: string;
	action: string;
	decision: "allow" | "deny";
	/** Present on deny — the first failing group's representative rule. */
	code?: string;
	/** Present on deny — the first failing group's representative rule. */
	message?: string;
	reason: DecisionReason;
}

/** One validated entry: the request as sent, plus its resource already parsed. */
export interface ValidatedDecisionRequest {
	request: DecisionRequest;
	resource: Resource;
}

/**
 * What one decision needs beyond its entry: who is asking, what of the
 * transport may reach the collectors, how the decision is correlated, and
 * until when it is wanted. Nothing here is an Express type; the router builds
 * one per request and hands it to every entry's decision.
 */
export interface DecisionInput {
	/** The subject the authenticator established from the presented credential. */
	subject: SubjectAttributes;
	/**
	 * The presented credential, only when the composition exposes it to
	 * collectors (`credentialToCollectors: "expose"`, #175). Absent — or present
	 * without a value, which only a `TokenAuthenticator` written in JavaScript
	 * can produce — the collector context carries no `credential` key at all:
	 * the decision never holds the token unless it is meant to reach a
	 * collector.
	 */
	credential?: string;
	/**
	 * The headers the collectors may read, as `CollectorContext.headers` — the
	 * transport's choice of what crosses (today the caller's `x-request-id`,
	 * #200), made once per request rather than in here. Every decision of the
	 * request shares this input; each hands its collectors its own copy, so one
	 * entry of a batch cannot reach another's through it.
	 */
	headers?: Record<string, string>;
	/**
	 * The request id the transport accepted (`acceptRequestId`), or none. It is
	 * the value `headers` carries and the value every line about this decision
	 * is correlated by; the two are separate inputs because they answer to
	 * different readers — collectors and the log.
	 */
	requestId?: string;
	/** Aborts when the caller went away: the collectors and the evaluator stop with it. */
	signal: AbortSignal;
}

/**
 * What every decision shares, resolved once by whoever builds the decider: the
 * pipelines, the evaluator's settings, and where decisions are reported. The
 * router resolves each numeric bound at its own boundary (#157) and hands the
 * numbers over; nothing here reads config, defaults anything, or refuses
 * anything — that is the router's contract, stated in its own words.
 */
export interface DeciderConfig {
	attributePipeline: AttributePipeline;
	rulePipeline: RulePipeline;
	/**
	 * Evaluator semantics overrides, without the deadlines and the failure
	 * record: the deadlines are the two fields below, and the record is one per
	 * decision, made here (#200). A `signal` in here is a library consumer's own
	 * and is combined with the caller's, never replaced by it.
	 */
	evaluateOptions?: Omit<EvaluateOptions, "ruleTimeoutMs" | "evaluateDeadlineMs" | "failures">;
	/** How long one asynchronous rule may take to answer (#225). */
	ruleTimeoutMs: number;
	/** How long all of a decision's asynchronous rules may take together. */
	evaluateDeadlineMs: number;
	/** Whether the response carries each rule's `evaluation` (#244); the `decision` line always does. */
	includeEvaluation: boolean;
	/** Where the `decision` line and the three deny events go. */
	logger: EventLogger;
	/** Optional counter seam (#111); omitted means decisions are logged but not counted. */
	metrics?: DecisionMetrics;
}

/** Decides one already-validated entry. See {@link createDecider}. */
export type Decider = (
	entry: ValidatedDecisionRequest,
	input: DecisionInput,
) => Promise<DecisionResponse>;

/**
 * The deny a collector fan-out that ran out of time is answered with (#115).
 *
 * A deny, and specifically not a 5xx. The caller asked whether this request is
 * authorized; what the verifier can stand behind when a collector stalled is
 * "not established", and the safe rendering of that is a refusal. A 500 invites
 * the enforcement layer to retry the same stalled dependency, or to conclude the
 * PDP is down and apply a fallback of its own — and a fallback nobody in this
 * repo wrote is precisely the fail-open being closed here.
 *
 * The message is fixed and says nothing about which collector or which bound:
 * that reaches the caller, and the collector set is deployment topology. The
 * detail is in the `collector_timeout` log line instead, where an operator can
 * act on it.
 */
const COLLECTOR_TIMEOUT_CODE = "collector_timeout";
/** An asynchronous rule that did not answer in time (#225): the same deny, its own code. */
const RULE_TIMEOUT_CODE = "rule_timeout";
const COLLECTOR_TIMEOUT_MESSAGE = "Authorization could not be decided in time";
/**
 * Deliberately the collector timeout's wording: to the caller a rule that did
 * not answer in time is the same event as a collector that did not — a
 * deadline elapsed — and which internal stage stalled is the log's business,
 * not the response's. The alias exists so the reuse reads as intent.
 */
const RULE_TIMEOUT_MESSAGE = COLLECTOR_TIMEOUT_MESSAGE;

const ATTRIBUTE_CONFLICT_CODE = "attribute_conflict";
const ATTRIBUTE_CONFLICT_MESSAGE = "Authorization inputs conflicted";

/**
 * The failure categories a decision is denied on rather than failed with, and
 * the deny each is answered with. Read off the category rather than tested
 * class by class, so the deny the caller gets and the `category` the log line
 * carries are one decision made once (#200).
 */
const DENIED_FAILURES: Partial<Record<FailureCategory, { code: string; message: string }>> = {
	collector_timeout: { code: COLLECTOR_TIMEOUT_CODE, message: COLLECTOR_TIMEOUT_MESSAGE },
	rule_timeout: { code: RULE_TIMEOUT_CODE, message: RULE_TIMEOUT_MESSAGE },
	attribute_conflict: { code: ATTRIBUTE_CONFLICT_CODE, message: ATTRIBUTE_CONFLICT_MESSAGE },
};

/**
 * What a decision that could not be made throws: the error as thrown, and the
 * classification only that decision's `FailureRecord` could make (#200). The
 * route unwraps it before anything is logged or compared, so `original` is
 * still the original error and the caller's abort reason is still recognised
 * by identity.
 */
export class DecisionFault extends Error {
	constructor(
		readonly original: unknown,
		readonly failure: ClassifiedFailure,
	) {
		super("the decision failed");
		this.name = "DecisionFault";
	}
}

/**
 * What a route caught, unwrapped: a decision's fault with its classification,
 * or anything else — the resource parser, the authenticator, the router's own
 * bookkeeping — as `internal`, whatever its class.
 */
export function unwrapFault(thrown: unknown): { cause: unknown; failure: ClassifiedFailure } {
	return thrown instanceof DecisionFault
		? { cause: thrown.original, failure: thrown.failure }
		: { cause: thrown, failure: { category: "internal" } };
}

/**
 * Builds the function that runs the pipelines and the evaluator for one
 * already-validated entry, and reports what it decided.
 *
 * A decision that could not be made throws a {@link DecisionFault}; the three
 * failures that are denies of their own — collector timeouts (#115), rule
 * timeouts (#225), attribute conflicts (#174) — are answered as denies here,
 * each with its own log line and, where a collector is answerable, its count.
 */
export function createDecider(config: DeciderConfig): Decider {
	const { logger, metrics, includeEvaluation, ruleTimeoutMs, evaluateDeadlineMs } = config;

	return async function decide(
		{ request: entry, resource }: ValidatedDecisionRequest,
		{ subject, credential, headers, requestId, signal }: DecisionInput,
	): Promise<DecisionResponse> {
		// `subject` was populated from a credential the authenticator verified and
		// `headers` were read off the transport; `entry.context` is whatever the
		// caller put in the body, so it crosses into the collector layer marked as
		// such. A collector has to unwrap it, which is where its author decides
		// what a caller may choose — see `UntrustedRequestContext` in core.
		const context = {
			subject,
			resource,
			action: entry.action,
			// A copy per decision, as the router built one per decision before the
			// extraction: the input is shared by every entry of a batch.
			headers: headers === undefined ? undefined : { ...headers },
			requestContext: entry.context ? markUntrustedRequestContext(entry.context) : undefined,
			// #175: absent unless the composition said "expose" — see
			// `DecisionInput.credential`. Spread-conditional on the value, so the
			// default context carries no `credential` key at all, not an undefined
			// one — and neither does a context whose authenticator supplied none.
			...(credential !== undefined ? { credential } : {}),
			// The caller going away cancels the collectors in flight (v0.10.0 audit).
			signal,
		};

		// Timed from here so the measurement is the decision itself — the two
		// pipelines plus evaluation — and not the HTTP round trip. One batch
		// request is many decisions, and it is the per-decision cost that a
		// collector reaching out to a store makes worse.
		const startedAt = performance.now();
		// #200: where this decision's failures came from, and only this one's.
		// Both collects and the evaluator record into it; nothing is kept beside
		// the error process-wide, where a concurrent decision failing on the same
		// shared object could overwrite it.
		const failures = new FailureRecord();
		let decision: Decision;
		try {
			const [attrs, rules] = await Promise.all([
				config.attributePipeline.collect(context, { failures }),
				config.rulePipeline.collect(context, { failures }),
			]);
			// #225: the rule list may carry asynchronous rules — an out-of-process
			// engine answers here, after both collects, where the evaluator
			// always ran. `ruleTimeoutMs` bounds each of them, `evaluateDeadlineMs`
			// all of them together.
			decision = await evaluate(attrs, rules, {
				...config.evaluateOptions,
				ruleTimeoutMs,
				evaluateDeadlineMs,
				// …and the asynchronous rule in flight, instead of leaving an
				// out-of-process call running to its budget for an answer nobody
				// will read — which a retrying caller multiplies. Combined with a
				// library consumer's own signal, never in place of it.
				signal:
					config.evaluateOptions?.signal === undefined
						? signal
						: AbortSignal.any([config.evaluateOptions.signal, signal]),
				failures,
			});
		} catch (cause) {
			// Three failures are denies of their own (#115 collector timeouts,
			// #225 rule timeouts, #174 attribute conflicts); anything else is a
			// genuine fault and keeps surfacing as a 500 — carrying the
			// classification only this decision's record could make.
			const failure = classifyFailure(cause, failures);
			const denial = DENIED_FAILURES[failure.category];
			if (denial === undefined) throw new DecisionFault(cause, failure);
			// The evaluator is deliberately never reached: it is the one place a
			// short rule list could still be read as a policy, and `onEmptyRuleSet:
			// "allow"` would then turn a timed-out (or conflicted) pipeline into a
			// permit. A deny is built here instead, with an empty `reason` because
			// no rule group was evaluated — which is the honest account of what
			// happened. The conflicted attribute KEY reaches the log line via the
			// error — held to the identifier shape, as the rule a timeout names is
			// (#200); the caller's message names neither key nor values.
			logger.error(
				{
					err: loggableError(cause, failure),
					resource: entry.resource,
					action: entry.action,
					...correlation(requestId),
					...failure,
				},
				denial.code,
			);
			countCollectorFailure(metrics, failure);
			decision = {
				decision: "deny",
				code: denial.code,
				message: denial.message,
				reason: { groups: [] },
			};
		}
		const durationMs = performance.now() - startedAt;

		// Derived once and spent twice — on the audit line below and on the
		// response returned at the end (#158). An empty `sub` is absent from both,
		// and the only way the two dispositions of one value cannot drift apart
		// again is for there to be one value.
		const subjectId = typeof subject.sub === "string" ? present(subject.sub) : undefined;

		// #111: one structured line per decision, and the counters beside it. Both
		// are emitted here rather than at each route so a decision is reported
		// exactly once whether it came through `/verify` or one entry of a batch.
		logger.info(
			decisionEvent({
				decision,
				subject: subjectId,
				resource: entry.resource,
				action: entry.action,
				requestId,
				durationMs,
			}),
			DECISION_EVENT,
		);
		metrics?.observe({
			decision: decision.decision,
			// `resource` and `action` are deliberately not passed: they come from
			// the request body and would be unbounded metric labels. They are on
			// the log line above instead.
			code: decision.decision === "deny" ? decision.code : undefined,
			durationSeconds: durationMs / 1000,
		});

		return toResponse(subjectId, entry, decision, includeEvaluation);
	};
}

/**
 * Projects an engine `Decision` onto the wire contract, naming what it was about.
 *
 * Takes the already-derived `subject` id rather than the subject bag: the audit
 * line and this response must agree about whether the decision had one, and
 * reading `subject.sub` a second time here is what let them disagree (#158).
 *
 * `includeEvaluation` is `verify.evaluationInResponse` (#244). The `decision`
 * event is built from the same `Decision` and always carries the evaluations,
 * so what the response includes is the event's own values, and what it omits
 * is still on the record.
 */
function toResponse(
	subject: string | undefined,
	entry: DecisionRequest,
	decision: Decision,
	includeEvaluation: boolean,
): DecisionResponse {
	const base = {
		...(subject !== undefined ? { subject } : {}),
		resource: entry.resource,
		action: entry.action,
		reason: includeEvaluation ? decision.reason : withoutEvaluations(decision.reason),
	};
	return decision.decision === "deny"
		? { ...base, decision: "deny", code: decision.code, message: decision.message }
		: { ...base, decision: "allow" };
}

/**
 * The reason with every outcome's `evaluation` left out (#244) — and nothing
 * else. Groups and outcomes are spread rather than rebuilt from a list of
 * keys, so whatever else either carries, now or later, stays. `satisfiedBy` is
 * rebuilt as the last evaluated outcome, which is what it is (#135), so the two
 * cannot differ in what was omitted.
 */
function withoutEvaluations(reason: DecisionReason): DecisionReason {
	return {
		groups: reason.groups.map((group) => {
			const evaluated = group.evaluated.map(({ evaluation: _evaluation, ...outcome }) => outcome);
			return group.passed
				? { ...group, evaluated, satisfiedBy: evaluated[evaluated.length - 1] }
				: { ...group, evaluated };
		}),
	};
}
