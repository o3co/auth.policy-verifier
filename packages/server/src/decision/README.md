# Decision

Last updated: 2026-09-24

## Responsibility

- **Role.** One decision, without the transport: run the attribute and rule
  pipelines for one already-validated entry, evaluate, sort a failure into a
  deny the caller gets or a fault the route answers, and report the decision.
  It is what `POST /verify` runs once and `POST /verify/batch` runs per entry.
  The entry point is `createDecider` in [`decide.mts`](decide.mts).
- **Owns.** The `decision` line and the counters for every decision that was
  made, and the wire types `DecisionRequest` and `DecisionResponse`: the
  decision consumes the one and produces the other, and must not import
  `../routes/`, so they are defined here and `../routes/` re-exports them.
- **Does not own.** Validating the wire body, authenticating the caller or the
  subject, status codes, headers — it never sees an Express `Request` or
  `Response`. Reading configuration or defaulting anything: the router
  resolves every bound at its own boundary (#157) and hands it over as a
  number. Reporting a fault: the route reports it once per request, because a
  fault speaks for the request.
- **Why a separate module.** So the decision can be held to a dependency
  boundary the router cannot be (see Dependencies): what one decision does is
  testable without Express, and `/verify` and `/verify/batch` cannot drift
  apart, because both call the same `Decider`. It lives in the server and not
  in core because it is the server's decision: it writes the server's
  `decision` line, sorts failures into the server's closed failure categories
  and counts through the server's `DecisionMetrics` port, all in
  [`../observability/`](../observability/). Core stays dependency-free and
  runtime-neutral and provides only the pipelines and `evaluate` it composes.

## Invariants

- Internal to the server package: nothing here is exported from
  [`../index.mts`](../index.mts).
- One decision, one `decision` line, one `observe`, whether it came through
  `/verify` or as one entry of a batch. A decision that could not be made
  throws `DecisionFault` and reports nothing; `unwrapFault` hands the route the
  original error, so the caller's own abort reason is still recognised by
  identity.
- A collector timeout, a rule timeout and an attribute conflict are denies of
  their own, with an empty `reason`, and the evaluator is never reached for
  them: `onEmptyRuleSet: "allow"` must not turn a timed-out or conflicted
  pipeline into a permit. Each writes one line carrying its `category`, and a
  collector is counted exactly when the category names one.
- The subject is trusted input from the authenticator, never from the body;
  the caller's `context` crosses into the collectors marked untrusted. The
  credential is held only when the composition exposes it to collectors.
- Nothing about a failure is kept process-wide. Each decision has its own
  `FailureRecord` and its own copy of the shared headers, so neither reaches
  another decision. The subject is not copied: it is one object shared by
  every entry of a batch, `readonly` only at its top level and only by type —
  a nested array claim can be written even from typed code once narrowed —
  so a collector must not write to it.
- The caller's signal cancels the collectors in flight and the asynchronous
  rule; a library consumer's `evaluateOptions.signal` is combined with it,
  never replaced by it. The rule deadlines are this module's own inputs, not
  read from `evaluateOptions`.
- `durationMs` covers the two collects and the evaluation only, never the HTTP
  round trip.

These are pinned through `createDecider` alone by
[`__tests__/decide.test.mts`](__tests__/decide.test.mts), and on the wire by the
router tests in [`../__tests__/`](../__tests__/), with these gaps: the
`onEmptyRuleSet: "allow"` rule is pinned only for a collector timeout, end to end
in [`../__tests__/app.test.mts`](../__tests__/app.test.mts); that the caller's
signal reaches the collectors is untested here (the pipelines' own half is in
core's [`collectorLimits.test.mts`](../../../core/src/__tests__/collectorLimits.test.mts));
the per-decision `FailureRecord` and the span of `durationMs` are not tested.

## Dependencies

- May import `@o3co/auth.policy-verifier.core` and
  [`../observability/`](../observability/), and nothing else.
- Must not reach `express`, `prom-client`, `../http/`, `../jwt/`, `../config/`
  or `../routes/`, directly or through anything it imports.
- Reaches the metrics implementation (`../observability/metrics.mts`, which
  loads express and prom-client) through no import at all, type-only included:
  it counts through the `DecisionMetrics` port.

Pinned by [`__tests__/dependencies.test.mts`](__tests__/dependencies.test.mts),
which also shows, on the router and on the metrics implementation, that each of
its walks fires. Only `../routes/` imports this directory.
