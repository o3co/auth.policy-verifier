# Rules

Last updated: 2026-09-24

The built-in rules — predicates over attributes — and, under `collectors/`, the two rule
collectors that build them from the request.

## Responsibility

- **Role.** The rule side of `@o3co/auth.policy-verifier.builtins`: core's `RulePipeline` runs
  the rule collectors here, core's `evaluate()` asks the rules they return, and a host may
  construct any rule class itself.
- **Owns.** What each rule compares and how — its matching, its refusals of bad
  configuration, its default `ruleType` and `code` — and, for the rule collectors, which rule
  a request gets.
- **Does not own.** The grouping or the decision (core's `evaluate()`), the attributes
  (produced by [`../collectors/`](../collectors/README.md)), or any rule that needs I/O: every
  rule here is a synchronous `Rule`, and `AsyncRule`s are `packages/cedar`'s or the
  consumer's.
- **Why a separate module.** Collectors read the request, rules read `attrs`
  (o3co/auth.policy-verifier#251). Within this directory the line runs between the rules and
  `collectors/`: the rule collectors are the only code here that sees a `CollectorContext`.
  They read it inside `collect` and copy strings out, and the rule they return holds those
  strings and nothing of the request.

Options and matching: [`../../README.md`](../../README.md#rules).

## Public contract

The rule and rule-collector classes and their config types are exported from
[`../index.mts`](../index.mts); the rule collectors are also registered by
[`../module.mts`](../module.mts). What a rule is, is core's `Rule` in
[`types.mts`](../../../core/src/types.mts); what it must be — a deterministic, side-effect-free
function of `attrs` that retains nothing of the `CollectorContext` — is
[AGENTS.md — Collector / Rule / Attribute Contract](../../../../AGENTS.md#collector--rule--attribute-contract).

## Inputs and outputs

A rule takes the merged `ReadonlyAttributes` and answers a boolean. A rule collector takes a
`CollectorContext` and returns a rule built fresh for that request — or, for the scope
collector under `scopeless: "skip"` with no scope claim, no rule at all. `ruleType` and `code`
reach the wire and the failure lines. No rule here reports an evaluation.

## Dependencies

`@o3co/auth.policy-verifier.core`, files in this directory, and one file of
[`../collectors/`](../collectors/README.md): the scope rule collector imports `_claims.mts` so
that it and `PayloadScopeCollector` share the default claim name and the refusal of a bad
`claim` option. That is the only edge from `rules/` into `collectors/`; none runs the other
way, and nothing here imports `../resource/`. Inside, the rule collectors depend on the rules,
never the reverse.

## Invariants

- Collect the rule, discard the request, ask again: the answer is unchanged. The rule-purity
  suite, [`rulePurity.mts`](../../../../tests/integration/src/conformance/rulePurity.mts), is
  applied to both rule collectors in
  [`rule-purity-conformance.test.mts`](../../../../tests/integration/src/rule-purity-conformance.test.mts);
  apply it to every rule collector you add. The CI step "Assert no verify() body reads a
  collector context" in [`ci.yml`](../../../../.github/workflows/ci.yml) greps `verify`
  bodies as a textual backstop. No builtin collector emits the comparison rules, so beyond
  that grep their purity is documented, not tested.
- An attribute that is missing, `null`, `NaN` or of another type than the rule's literal
  never throws and answers `false`; matching is exact and case-sensitive — the per-rule tests
  in [`../__tests__/rules/`](../__tests__/rules/). `NaN` needs saying: it is unequal to every
  number and in no set, so `AttrLiteralNotEqual` and `AttrLiteralNotIn` refuse it by name
  rather than let it pass as an unequal value.
- Configuration is refused at construction: an attribute name may not contain `:` (the
  `ruleType` separator), a literal may not be `NaN`, a value list is non-empty and
  homogeneous, `group` is a non-empty string; the default `ruleType` tells `1` from `"1"` and
  ignores value order and duplicates —
  [`_sharedValidation.test.mts`](../__tests__/rules/_sharedValidation.test.mts).
- A rule keeps only its own copy of its configuration, taken at construction: a caller that
  mutates the config object afterwards changes neither the answers nor `ruleType` and
  `message`, and cannot install a value the constructor refuses —
  [`configCopiedAtConstruction.test.mts`](../__tests__/rules/configCopiedAtConstruction.test.mts).
  A rule may therefore answer concurrent decisions.

## Failure and lifecycle

Where there is configuration to refuse, the constructor throws an `Error` naming the
validating class and the field — at boot for a deployment that builds its rules from
configuration at startup, and whenever it constructs one otherwise. Nothing here does I/O: a
synchronous rule runs under no rule budget, and the rule collectors run under the pipeline's
per-collector timeout and deadline like any collector; `signal` is never read.
