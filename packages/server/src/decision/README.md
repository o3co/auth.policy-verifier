# Decision

One decision, without the transport (o3co/auth.policy-verifier#251).

## Responsibility

Runs the attribute and rule pipelines for one already-validated entry,
evaluates, sorts a failure into a deny the caller gets or a fault the route
answers, and reports the decision once: the `decision` line and the counters.
It is what `POST /verify` runs once and `POST /verify/batch` runs per entry.

It does not validate the wire body, authenticate the caller or the subject,
choose status codes, or write headers, and it never sees an Express `Request`
or `Response`. It does not read configuration or default anything: every bound
is resolved by the router at its own boundary (#157) and handed over as a
number.

## Public contract

Internal to the server package; nothing here is exported from
[`../index.mts`](../index.mts).

- [`createDecider(config)`](decide.mts) returns a `Decider`, which decides one
  `ValidatedDecisionRequest` given a `DecisionInput`.
- `DeciderConfig` — the pipelines, the evaluator's settings, the logger and the
  optional metrics seam; `DecisionInput` — what one request's decisions share.
- `DecisionFault` and `unwrapFault` — how a decision that could not be made is
  handed to the route.
- `DecisionRequest` and `DecisionResponse` — the wire types, defined here and
  re-exported by [`../routes/verify.mts`](../routes/verify.mts), where they were
  exported from before. Neither is on `../index.mts`.

## Inputs and outputs

- `subject` is trusted: the authenticator established it from a credential it
  verified. Core reads no field of it (`SubjectAttributes`); this module reads
  `sub` once, to name the subject on the line and the response.
- `credential` is present only when the composition exposes it
  (`credentialToCollectors: "expose"`, #175). Absent — or present without a
  value, which only a `TokenAuthenticator` written in JavaScript can produce —
  the collector context carries no `credential` key at all: the decision never
  holds the token unless it is meant to reach a collector.
- `headers` is the transport's choice of what collectors may read (today the
  caller's `x-request-id`, #200); `requestId` is the correlation of every line
  about the decision. Both are built once per request by the router; each
  decision hands its collectors its own copy of `headers`, so one entry of a
  batch cannot reach another's through it.
- `entry.request.context` is the caller's, and crosses into the collectors
  marked untrusted (`markUntrustedRequestContext`); a collector unwraps it.
- The answer is a `DecisionResponse`. `subject` is absent when the token has no
  `sub` or an empty one, on the response and on the line alike (#158).
  `reason` carries each outcome's `evaluation` only when `includeEvaluation` is
  set; the `decision` line always carries what the rules reported (#244).

## Dependencies

Imports `@o3co/auth.policy-verifier.core` (the pipelines, `evaluate`,
`FailureRecord`, `markUntrustedRequestContext`) and
[`../observability/`](../observability/) (the decision line, the failure
sorting, the counter helper). It must not reach `express`, `prom-client`,
`../http/`, `../jwt/`, `../config/` or `../routes/` — directly or through
anything it imports: `observability/metrics.mts` loads express and prom-client,
so the decision takes only the `DecisionMetrics` type from it, and the counter
helper lives in `observability/failure.mts`.
[`__tests__/dependencies.test.mts`](__tests__/dependencies.test.mts) walks the
value imports transitively and holds this; it also shows on the router that the
walk fires. [`../routes/verify.mts`](../routes/verify.mts) imports this module;
nothing else does.

## Invariants

- One decision, one `decision` line, one `observe` — whether it came through
  `/verify` or as one entry of a batch. A decision that could not be made
  reports nothing here; the route reports the fault once per request, because a
  fault speaks for the request (a batch's 500 is one line for the batch, #200).
- The three failures that are denies of their own — a collector timeout (#115),
  a rule timeout (#225), an attribute conflict (#174) — are answered from
  `DENIED_FAILURES` with an empty `reason`, and the evaluator is never reached
  for them: `onEmptyRuleSet: "allow"` must not turn a timed-out pipeline into a
  permit. Each writes one line carrying its `category`, and a collector is
  counted exactly when the category names one.
- Each decision has its own `FailureRecord`; nothing about a failure is kept
  process-wide (#200).
- A library consumer's `evaluateOptions.signal` is combined with the caller's,
  never replaced by it; `ruleTimeoutMs` and `evaluateDeadlineMs` are this
  module's inputs and are not read from `evaluateOptions`.
- `durationMs` covers the two collects and the evaluation only, never the HTTP
  round trip.

## Failure and lifecycle

- A fault throws `DecisionFault { original, failure }`; `unwrapFault` hands the
  route the original error, so the caller's own abort reason is still
  recognised by identity (`verify_caller_gone`, never a 500 for it).
- The caller's `signal` cancels the collectors in flight and the asynchronous
  rule; the decision then fails with the caller's reason.
- Deadlines: `ruleTimeoutMs` per asynchronous rule, `evaluateDeadlineMs` for
  all of them together; the collector deadlines are the pipelines' own.

## Contract tests

- [`__tests__/decide.test.mts`](__tests__/decide.test.mts) — the invariants
  above through `createDecider` alone, with two exceptions that are documented
  rather than tested: the per-decision `FailureRecord` is not observable from
  outside, and `durationMs` is asserted to be a number only.
- [`__tests__/dependencies.test.mts`](__tests__/dependencies.test.mts) — the
  dependency boundary.
- The same contracts on the wire, through the router:
  [`../__tests__/verify.test.mts`](../__tests__/verify.test.mts),
  [`../__tests__/failureTriage.test.mts`](../__tests__/failureTriage.test.mts),
  [`../__tests__/decisionLogging.test.mts`](../__tests__/decisionLogging.test.mts),
  [`../__tests__/metrics.test.mts`](../__tests__/metrics.test.mts),
  [`../__tests__/evaluationProvenance.test.mts`](../__tests__/evaluationProvenance.test.mts).
