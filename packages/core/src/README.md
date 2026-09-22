# Core

The engine's contract and the two things that run it — the collector pipelines and
`evaluate()`. Nothing here is a transport or a policy engine.

## Responsibility

Owns the vocabulary a decision is made in (`CollectorContext`, `Attributes`,
`AttributeCollector` / `RuleCollector`, `Rule` / `AsyncRule`, `Decision`) and the three steps
that reach one: the bounded fan-out of attribute collectors (`AttributePipeline`) and of rule
collectors (`RulePipeline`), then the evaluation of the collected rules over the merged
attributes (`evaluate()`). It fixes their semantics — OR within a group, AND across, default
deny, fail-closed bounds — with the errors, failure attribution and cancellation that go with
them; it holds the five `ATTR_*` keys and their reservation registry, the `Logger` port and
its `console` sink (the engine writes no log line itself), and the `Module` / `Registry`
shape a composition is built from.

It does not verify a credential: `subject` arrives established by a transport, and
`credential` is present only under the server's opt-in (#175) and read by nothing here. It
does no HTTP and no I/O, contains no policy engine (`AsyncRule` is the seam one sits behind;
`packages/cedar` is one), reads no field of `SubjectAttributes` (#170), and names no domain
attribute key — [AGENTS.md — Core Vocabulary Scope](../../../AGENTS.md#core-vocabulary-scope).
Every bound reaches it as a number; it reads no configuration.

## Public contract

Everything on [`index.mts`](index.mts); [`../README.md`](../README.md) shows usage.

- [`types.mts`](types.mts) — the contract types, `ReportRuleEvaluation` / `RuleEvaluation`
  with the revision grammar `POLICY_REVISION_PATTERN` / `POLICY_REVISION_MAX_LENGTH` (#244),
  `isAsyncRule`; [`untrusted.mts`](untrusted.mts) — `UntrustedRequestContext`,
  `markUntrustedRequestContext`, `readUntrustedRequestContext`.
- [`AttributePipeline`](AttributePipeline.mts), [`RulePipeline`](RulePipeline.mts) and their
  bounds in [`collectorLimits.mts`](collectorLimits.mts); [`evaluate`](evaluate.mts) and
  `EvaluateOptions`; [`FailureRecord`](failureSource.mts) / `FailureSource` (#200);
  [`errors.mts`](errors.mts).
- [`keys.mts`](keys.mts) — the `ATTR_*` constants, `CORE_ATTRIBUTE_KEY_OWNER`,
  `reserveAttributeKeys`, `RESERVED_ATTRIBUTE_KEYS`, `attributeKeyReservation`,
  `suggestUnreservedAttributeKey`.
- [`logging/`](logging/) — `Logger`, `EventLogger`, `consoleLogger`; [`modules/`](modules/) —
  `Module`, `ModuleContext`, the factory types, `Registry`.

## Inputs and outputs

- A pipeline takes a `CollectorRequest` — `subject`, `resource`, `action`, optional `headers`,
  `requestContext`, `credential` and the caller's `signal` — and hands each collector a
  `CollectorContext`: the same, with the caller's `signal` replaced by one minted per collector
  per decision and linked to it, so a collector never holds the caller's own. Every field but
  one is vouched for by whoever built it; `requestContext` is the caller's and crosses sealed —
  marked by the transport with `markUntrustedRequestContext`, unwrapped by a collector with
  `readUntrustedRequestContext`, which is the acknowledgement.
- `AttributePipeline.collect` returns one merged `Attributes`: array-valued keys concatenate
  in collector order, a scalar is written once or re-written identically, and two different
  scalars under one key are an `AttributeConflictError`. `RulePipeline.collect` concatenates.
- `evaluate(attrs, rules, options)` returns a `Decision`: allow, or deny with the `code` /
  `message` of the first rule of the first failing group; `reason` accounts for every group,
  each outcome carrying what its rule reported (#244).

## Dependencies

Imports nothing outside this directory: every non-test import is relative, and `package.json`
declares no `dependencies` (the tests import `vitest`). Imported as a dependency by
`builtins`, `cedar`, `server`, `tests/integration` and `templates/standalone`, and by
`cedar-wasm` for its tests. No lint holds the boundary — documented, not tested.

## Invariants

- A bound that trips fails the collect — no partial map, no shorter rule list — and a
  collector whose decision is already lost is not invoked at all; an unusable limit is refused
  at construction, above `MAX_TIMER_MS` included —
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
  read at verify time is the conformance suite below.
- One reporter per invocation (#244): at most one report, checked and frozen onto that
  outcome alone; a non-boolean answer, a report that does not read or a pass reporting
  `failed` / `not_invoked` is a `TypeError` attributed to the rule even when the rule
  swallowed it — [`__tests__/ruleEvaluationReport.test.mts`](__tests__/ruleEvaluationReport.test.mts).
- Attribution is opt-in and partial: only when the caller hands a `FailureRecord` in, and only
  for what the runner and evaluator raise or observe themselves — a collector's failure or
  budget, a pipeline's deadline, a rule's failure or budget — is the source recorded beside
  the error, never wrapped around it. The record lives one decision; the first source wins;
  the caller's abort is attributed to nobody, and neither is anything outside those paths (a
  merge conflict, a parser's error, an unusable bound), so `sourceOf` answers `undefined` for
  them — [`__tests__/failureSource.test.mts`](__tests__/failureSource.test.mts).
- The reservation registry is live; a key has one owner; reserving is idempotent per owner
  and all-or-nothing per call — [`__tests__/keys.test.mts`](__tests__/keys.test.mts).
  `requestContext` cannot be read without the accessor, by type —
  [`__tests__/untrusted.test.mts`](__tests__/untrusted.test.mts).

## Failure and lifecycle

- Three failures are denies of their own, distinct classes so a transport answers them
  without a 500: `CollectorTimeoutError` (a collector's budget or a pipeline's deadline, #115),
  `AttributeConflictError` (#174), `RuleTimeoutError` (#225). Each names what is answerable and
  never an attribute value: the collector that overran its budget, or only the pipeline when
  its deadline as a whole expired (`collector` is then absent); the conflicting key; the rule.
- Everything else is rethrown unchanged: a collector's or rule's own error (a fault), the
  caller's abort reason (recognisable by identity), the `TypeError`s above. A `RangeError` for
  an unusable bound is thrown before anything runs; `ResourceParseError` is a parser's request
  error, for the transport to answer as a 400.
- The caller's `signal` cancels every collector in flight and the asynchronous rule; a
  sibling's failure or a deadline cancels the rest of the wave. Timers are cleared and
  listeners removed per decision.

## Contract tests

The `__tests__/` files above, with [`AttributePipeline.test.mts`](__tests__/AttributePipeline.test.mts)
(the merge), [`RulePipeline.test.mts`](__tests__/RulePipeline.test.mts),
[`Registry.test.mts`](__tests__/Registry.test.mts), [`errors.test.mts`](__tests__/errors.test.mts)
and [`logging/__tests__/`](logging/__tests__/); `Module` / `ModuleContext` are exercised by
the builtins module test and the server's `createApp`, not here. Across packages: the
rule-purity suite [`rulePurity.mts`](../../../tests/integration/src/conformance/rulePurity.mts),
which asks through `evaluate()`, and the registry across package boundaries in
[`reserved-attribute-keys.test.mts`](../../../tests/integration/src/reserved-attribute-keys.test.mts).
