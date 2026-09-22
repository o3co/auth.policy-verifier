# Rules

The built-in rules — predicates over attributes — and, under [`collectors/`](collectors/), the
two rule collectors that build them from the request.

## Responsibility

A rule here answers one question about `attrs` and holds nothing else: what it compares
against is fixed when it is constructed — from configuration or, for the two collected rules,
from the request at collect time.

- [`HasScope`](HasScope.mts) — `ATTR_SCOPES` contains the required scope; `ruleType` `scope`,
  `code` `invalid_scope`. Exact and case-sensitive; the bare `x` → `read:x` rewrite is opt-in
  (`allowBareScopeRewrite`).
- [`HasPermission`](HasPermission.mts) — `ATTR_PERMISSIONS`, or a role in `ATTR_ROLES`, grants
  the required permission; `permission` / `no_permission`. Exact and case-sensitive; one `*`
  in a *granted* permission is honoured, and its halves may not overlap (#180).
- The comparison rules [`AttrLiteralEqual`](AttrLiteralEqual.mts),
  [`AttrLiteralNotEqual`](AttrLiteralNotEqual.mts), [`AttrLiteralIn`](AttrLiteralIn.mts),
  [`AttrLiteralNotIn`](AttrLiteralNotIn.mts), [`AttrLiteralCompare`](AttrLiteralCompare.mts),
  [`AttrPairEqual`](AttrPairEqual.mts), [`AttrPairNotEqual`](AttrPairNotEqual.mts) and
  [`AttrPairCompare`](AttrPairCompare.mts) — an operator-named attribute against a literal or
  another attribute, with no coercion; the default `ruleType` is derived from the config so
  distinct requirements AND, and `group` makes two OR. [`AttrMatchRule`](AttrMatchRule.mts) is
  the deprecated wrapper of `AttrPairEqual`, keeping its legacy `ruleType` and message.

Every rule here is a synchronous `Rule`; this package ships no `AsyncRule` (the Cedar rules
are `packages/cedar`'s). Options and matching: [`../../README.md`](../../README.md#rules).

### `collectors/` — the layer that reads the request

[`ResourceActionScopeRuleCollector`](collectors/ResourceActionScopeRuleCollector.mts) reads
`context.action` and `context.resource.resourceType` — and, under `scopeless: "skip"` only,
whether `context.subject` carries the scope claim — and returns a `HasScope` for
`<action>:<resourceType>`;
[`ResourceActionPermissionRuleCollector`](collectors/ResourceActionPermissionRuleCollector.mts)
reads `context.resource.raw` and `context.action` and returns a `HasPermission` for
`<resource.raw>.perm:<action>`. They are the only things here that see a `CollectorContext`:
they read it inside `collect`, copy strings out, and the rule they return holds those strings
and nothing of the request. That is the split — collectors read the request, rules read
`attrs` — and o3co/auth.policy-verifier#251 holds V2 (moving this directory beside
`../collectors/`) as decided by whether this README makes it clear.

## Public contract

The classes above and their config types, exported from [`../index.mts`](../index.mts); the
two collectors are also registered by [`../module.mts`](../module.mts). What a rule is, is
core's `Rule` in [`types.mts`](../../../core/src/types.mts); what it must be is
[AGENTS.md — Collector / Rule / Attribute Contract](../../../../AGENTS.md#collector--rule--attribute-contract),
stated here as it stands there and not tightened:

- `verify` must be a deterministic, side-effect-free function of `attrs`: equal attributes
  give equal answers, and it must not mutate its input, perform I/O, or observe anything the
  engine cannot see. It is handed a `ReadonlyAttributes`, so the "must not mutate" half is a
  compile error rather than a request.
- An `AsyncRule.decide` is the one exception to "no I/O", and only to that clause: everything
  else holds — the answer is a function of `attrs` alone, the `CollectorContext` may not be
  retained and read, the attributes may not be mutated — and the purity conformance suite
  checks `decide` exactly as it checks `verify`.
- A rule may hold values fixed at collect time — what it looks for. It must not retain
  `CollectorContext`, or any live reference into it, and read it inside `verify`. `signal` is
  on the same side of that line: a collector may hold it for the duration of `collect`; a
  rule must not carry it into `verify`.
- `report` is the one thing a rule may write to, and it is not a side effect (#244): the
  reporter is made per call and dead after it, and what is reported is part of one
  evaluation's result, held to the same rule — equal attributes, equal report.

## Inputs and outputs

A rule takes the merged `ReadonlyAttributes` and answers a boolean; a value under the wrong
key, of the wrong type or malformed in any way answers `false` and never throws. A collector
takes a `CollectorContext` and returns a fresh rule per request. `ruleType` and `code` reach
the wire and the failure lines.

## Dependencies

The rules import `@o3co/auth.policy-verifier.core` and
[`_sharedValidation.mts`](_sharedValidation.mts) only; none imports `CollectorContext`. The
collectors import core, the rule they build, and
[`../collectors/_claims.mts`](../collectors/_claims.mts) — the one edge from `rules/` into
`collectors/`, so the scope rule collector and `PayloadScopeCollector` cannot disagree about
which claim holds the scopes. Imported by `../index.mts` and `../module.mts`.

## Invariants

- Collect the rule, discard the request, ask again: the answer is unchanged.
  `describeRulePurityConformance` in
  [`rulePurity.mts`](../../../../tests/integration/src/conformance/rulePurity.mts) runs that,
  applied to both collectors in
  [`rule-purity-conformance.test.mts`](../../../../tests/integration/src/rule-purity-conformance.test.mts).
  The CI step "Assert no verify() body reads a collector context" in
  [`ci.yml`](../../../../.github/workflows/ci.yml) greps `verify` bodies as a textual backstop;
  the suite is the check. No builtin collector emits the comparison rules, so they are not run
  through the suite: beyond the grep, their purity is documented, not tested.
- Malformed attributes never throw and never match; matching is exact and case-sensitive, a
  multi-colon scope is one value, and a wildcard's halves do not overlap —
  [`HasScope.test.mts`](../__tests__/rules/HasScope.test.mts),
  [`HasPermission.test.mts`](../__tests__/rules/HasPermission.test.mts) (the "malformed" and
  "(#180)" cases), and the safe-deny cases of each `Attr*` test.
- Configuration is refused at construction: an attribute name may not contain `:` (the
  `ruleType` separator), a literal may not be `NaN`, a value list is non-empty and
  homogeneous, `group` is a non-empty string; the default `ruleType` tells `1` from `"1"` and
  ignores value order and duplicates —
  [`_sharedValidation.test.mts`](../__tests__/rules/_sharedValidation.test.mts).
- The scope collector emits its rule for a scopeless token unless `scopeless: "skip"` is
  opted into, decides scopeless-ness from the configured `claim`, and refuses an unrecognised
  policy, a non-boolean rewrite flag or an empty claim at construction —
  [`ResourceActionScopeRuleCollector.test.mts`](../__tests__/rules/collectors/ResourceActionScopeRuleCollector.test.mts);
  the permission string is `<resource.raw>.perm:<action>` —
  [`ResourceActionPermissionRuleCollector.test.mts`](../__tests__/rules/collectors/ResourceActionPermissionRuleCollector.test.mts).

## Failure and lifecycle

A constructor throws an `Error` naming the class and the field; that is the only place
anything here throws, and it happens at boot. Nothing here does I/O, so no rule budget or
collector deadline is ever spent on it, and `signal` is never read. A rule keeps only its
configuration and may answer concurrent decisions; none reports an evaluation.

## Contract tests

[`../__tests__/rules/`](../__tests__/rules/) — one file per rule, the shared validation, and
[`collectors/`](../__tests__/rules/collectors/) for the two collectors; the purity suite and
its application named above; and the grouping the comparison rules rely on, end to end
through `evaluate()`, in
[`evaluate-with-rules.test.mts`](../../../../tests/integration/src/evaluate-with-rules.test.mts).
