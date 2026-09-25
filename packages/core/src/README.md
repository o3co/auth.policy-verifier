# Core

Last updated: 2026-09-25

The engine's contract and the two things that run it — the collector pipelines and
`evaluate()`. Nothing here is a transport or a policy engine.

## Responsibility

- **Role.** The bottom layer: `builtins`, `cedar` and `server` build on it, and it depends on
  nothing (see [Dependencies](#dependencies)).
- **Owns.** The vocabulary a decision is made in (`CollectorContext`, `Attributes`,
  `AttributeCollector` / `RuleCollector`, `Rule` / `AsyncRule`, `Decision`) and the three steps
  that reach one: the bounded fan-out of attribute collectors and of rule collectors, then the
  evaluation of the collected rules over the merged attributes. It fixes their semantics — OR
  within a group, AND across, default deny, fail-closed bounds — with the errors, failure
  attribution and cancellation that go with them. It also holds the five `ATTR_*` keys and
  their reservation registry, the `Logger` port and its `console` sink (the engine writes no
  log line itself), and the `Module` / `Registry` shape a composition is built from.
- **Does not own.** Credential verification: `subject` arrives established by a transport, and
  `credential` is present only under the server's opt-in and read by nothing here. HTTP, and on
  the request path any I/O of its own — `AsyncRule.decide` is the one seam through which a
  rule may do I/O, and `evaluate` runs it under the rule budget; the console logger in
  `logging/` is the one thing here that writes anywhere, an adapter a host replaces. A policy
  engine (`AsyncRule` is the seam one sits behind; `packages/cedar` is one). Any field of
  `SubjectAttributes`, or any domain attribute key —
  [AGENTS.md — Core Vocabulary Scope](../../../AGENTS.md#core-vocabulary-scope).
  Configuration: every bound reaches it as a number.
- **Why a separate module.** So that the contract every collector, rule and module is written
  against carries no transport, credential or policy engine with it and runs on the edge
  runtimes [`../README.md`](../README.md) lists — a deployment can replace the server or the
  builtins and keep this.

## Public contract

Everything exported from [`index.mts`](index.mts) — the entry point; the contract types live in
[`types.mts`](types.mts). [`../README.md`](../README.md) shows usage.

## Inputs and outputs

- A pipeline takes a `CollectorRequest` and hands each collector a `CollectorContext`: the
  same, with the caller's `signal` replaced by one minted per collector per decision and
  linked to it, so a collector never holds the caller's own. Every data field but one is
  vouched for by whoever built it; `requestContext` is the caller's and crosses sealed —
  marked by the transport with `markUntrustedRequestContext`, unwrapped by a collector with
  `readUntrustedRequestContext`, which is the acknowledgement.
- `AttributePipeline.collect` returns one merged `Attributes`: array-valued keys concatenate
  in collector order, a scalar is written once or re-written identically, and two different
  scalars under one key are an `AttributeConflictError`. `RulePipeline.collect` concatenates.
- `evaluate(attrs, rules, options)` returns a `Decision`: allow, or deny with the `code` /
  `message` of the first rule of the first failing group; `reason` accounts for every group,
  each outcome carrying what its rule reported. An empty rule set is the one deny in core's
  own words — `no_applicable_rule` — under the default `onEmptyRuleSet: "deny"`.

## Dependencies

Imports nothing outside this directory: every non-test import is relative, and `package.json`
declares no `dependencies`. Depended on by `builtins`, `cedar`, `server`, `tests/integration`
and `templates/standalone`, and by `cedar-wasm` for its tests. No lint holds the boundary —
documented, not tested.

## Invariants

- A bound that trips fails the collect — no partial map, no shorter rule list — and a
  collector whose decision is already lost is not invoked at all; an unusable limit is refused
  at construction —
  [`__tests__/collectorLimits.test.mts`](__tests__/collectorLimits.test.mts).
- OR within a `ruleType` group, AND across; every group is evaluated even after one fails;
  `evaluated` is what ran, `satisfiedBy` what decided; an empty rule set is a deny unless
  `onEmptyRuleSet: "allow"` — [`__tests__/evaluate.test.mts`](__tests__/evaluate.test.mts).
- An `AsyncRule` runs under `ruleTimeoutMs` and the phase's `evaluateDeadlineMs`, whichever
  ends first, and none starts once the phase is spent; a synchronous rule is not timed; the
  caller's `signal` aborts the rule in flight with the caller's reason —
  [`__tests__/asyncRules.test.mts`](__tests__/asyncRules.test.mts).
- `verify` is judged against a `ReadonlyAttributes`, by type and for determinism —
  [`__tests__/ruleContract.test.mts`](__tests__/ruleContract.test.mts); that no context is
  read at verify time is the cross-package rule-purity suite,
  [`rulePurity.mts`](../../../tests/integration/src/conformance/rulePurity.mts).
- One reporter per invocation: at most one report, checked and frozen onto that outcome
  alone; a non-boolean answer, a report that does not read or a pass reporting `failed` /
  `not_invoked` is a `TypeError` attributed to the rule even when the rule swallowed it.
  Determining policies are carried only by a `completed` evaluation, as a bounded set of ids
  with a count of what did not fit; they are refused on a `failed` or `not_invoked` one however
  the value is reached (as a revision is on `not_invoked`), and the one id check
  (`isReportablePolicyId`) is what `boundDeterminingPolicies` filters with —
  [`__tests__/ruleEvaluationReport.test.mts`](__tests__/ruleEvaluationReport.test.mts).
- Failure attribution is opt-in and partial: only when the caller hands a `FailureRecord` in,
  and only for what the runner and evaluator raise or observe themselves, is the source
  recorded — beside the error, never wrapped around it. The record lives one decision and the
  first source wins; the caller's abort, and anything outside those paths, is attributed to
  nobody — [`__tests__/failureSource.test.mts`](__tests__/failureSource.test.mts).
- The reservation registry is live; a key has one owner; reserving is idempotent per owner
  and all-or-nothing per call — [`__tests__/keys.test.mts`](__tests__/keys.test.mts), and
  across packages
  [`reserved-attribute-keys.test.mts`](../../../tests/integration/src/reserved-attribute-keys.test.mts).
- `requestContext` cannot be read without the accessor, by type —
  [`__tests__/untrusted.test.mts`](__tests__/untrusted.test.mts).

## Failure and lifecycle

- Three failures are denies of their own, distinct classes so a transport answers them
  without a 500: `CollectorTimeoutError`, `AttributeConflictError`, `RuleTimeoutError`. Each
  names what is answerable and never an attribute value.
- Everything else is rethrown unchanged: a collector's or rule's own error (a fault), the
  caller's abort reason (recognisable by identity), the `TypeError`s above. A `RangeError` for
  an unusable bound is thrown before anything runs; `ResourceParseError` is a parser's request
  error, for the transport to answer as a 400. The error classes live in
  [`errors.mts`](errors.mts).
- The caller's `signal` cancels every collector in flight and the asynchronous rule; a
  sibling's failure or a deadline cancels the rest of the wave. Timers are cleared and
  listeners removed per decision.
