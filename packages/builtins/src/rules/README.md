# Rules

The built-in rules — predicates over attributes — and, under [`collectors/`](collectors/), the
two rule collectors that build them from the request.

## Responsibility

A rule here answers one question about `attrs` and holds nothing else: what it compares
against comes from configuration, or for the two collected rules from the request at collect
time, and the rule never writes to it. The comparison rules keep the caller's
config object by reference and read `a`, `b`, `op` and `v` off it at verify time, while
`ruleType` and `message` are computed once in the constructor — so a host that constructs one
itself and then mutates the object it passed changes the answers, past the construction-time
guards and out of step with the `ruleType` the evaluator groups by. `HasScope` and
`HasPermission` take a string and keep nothing of the caller's. Nothing in the bundled
composition is exposed to this: [`module.mts`](../module.mts) registers the attribute
collectors, the two rule collectors and the resource parser — no comparison rule is
constructed there — and the rule collectors build their rules per request from the request
itself. It applies to a host that constructs one of these classes and keeps the object it
passed. Whether construction should copy or freeze it is #255.

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
  the deprecated subclass of `AttrPairEqual`, keeping its legacy `ruleType` and message.

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
`attrs` (o3co/auth.policy-verifier#251, V2).

## Public contract

The classes above, exported from [`../index.mts`](../index.mts) with the types of those that
take one — a `*Config` per comparison rule and for `AttrMatchRule`, `HasScopeOptions`,
`ResourceActionScopeRuleCollectorConfig` / `ScopelessPolicy`; `HasPermission` and
`ResourceActionPermissionRuleCollector` export none. The two collectors are also registered
by [`../module.mts`](../module.mts). What a rule is, is
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

A rule takes the merged `ReadonlyAttributes` and answers a boolean; a value that is missing,
`null` or of another type than the rule's literal answers `false` and never throws (the one
number the type guard admits but no rule wants, `NaN`, is the exception under
[Invariants](#invariants)). A collector
takes a `CollectorContext` and returns a rule built fresh for that request — or, for the scope
collector under `scopeless: "skip"` with no scope claim, no rule at all. `ruleType` and `code`
reach the wire and the failure lines.

## Dependencies

Every rule but `AttrMatchRule` imports `@o3co/auth.policy-verifier.core`; the eight comparison
rules also import [`_sharedValidation.mts`](_sharedValidation.mts); the one rule → rule edge is
`AttrMatchRule` subclassing `AttrPairEqual`, which is all it imports; `HasScope` and
`HasPermission` import core alone, and none imports `CollectorContext`. Each collector imports core and the rule it builds;
`ResourceActionScopeRuleCollector` also imports
[`../collectors/_claims.mts`](../collectors/_claims.mts) — the one edge from `rules/` into
`collectors/`: the same default claim name and the same refusal of a bad `claim` option as
`PayloadScopeCollector`, so that, configured with the same `claim`, the two read the same token
field. Each keeps its own option and nothing checks that both were given the same name, so a
deployment that sets `claim` sets it on both. Imported by `../index.mts` and `../module.mts`.

## Invariants

- Collect the rule, discard the request, ask again: the answer is unchanged.
  `describeRulePurityConformance` in
  [`rulePurity.mts`](../../../../tests/integration/src/conformance/rulePurity.mts) runs that,
  applied to both collectors in
  [`rule-purity-conformance.test.mts`](../../../../tests/integration/src/rule-purity-conformance.test.mts);
  apply it to every rule collector you add. The CI step "Assert no verify() body reads a
  collector context" in [`ci.yml`](../../../../.github/workflows/ci.yml) greps `verify` bodies
  as a textual backstop;
  the suite is the check. No builtin collector emits the comparison rules, so they are not run
  through the suite: beyond the grep, their purity is documented, not tested.
- An attribute that is missing, `null` or of another type than the rule's literal never throws
  and never matches; matching is exact and case-sensitive, a multi-colon scope is one value, and
  a wildcard's halves do not overlap —
  [`HasScope.test.mts`](../__tests__/rules/HasScope.test.mts),
  [`HasPermission.test.mts`](../__tests__/rules/HasPermission.test.mts) (the "malformed" and
  "(#180)" cases), and the safe-deny cases of each `Attr*` test. `NaN` is a number, so the type
  guard admits it, and what happens next differs by rule: the comparison rules answer `false`
  for every operator because a relational comparison with `NaN` is `false`, not because they
  check for it — [`AttrLiteralCompare.test.mts`](../__tests__/rules/AttrLiteralCompare.test.mts)
  and [`AttrPairCompare.test.mts`](../__tests__/rules/AttrPairCompare.test.mts) pin all four;
  `Equal` / `In` cannot match it; `AttrLiteralNotEqual` / `AttrLiteralNotIn` pass it as they
  pass any other unequal number, which is the one part documented and not tested, and whether
  it should be a deny is #254. A `NaN` *literal* is a different thing and is refused at
  construction, with its own case in each test.
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

Where there is configuration to refuse — the comparison rules, the scope collector — the
constructor throws an `Error` naming the validating class and the field, when the rule is
constructed — at boot for a deployment that builds its rules from configuration at startup,
and whenever it constructs one otherwise. That is the rule's own class everywhere but [`AttrMatchRule`](AttrMatchRule.mts), the deprecated wrapper,
which extends `AttrPairEqual` and validates through `super`, so its refusals name
`AttrPairEqual`. `HasScope`, `HasPermission` and `ResourceActionPermissionRuleCollector`
validate nothing. Nothing here
does I/O: a synchronous rule runs under no rule budget, the collectors run under the
pipeline's per-collector timeout and deadline, which are in force — they do no I/O and complete
within any usable bound, though an aborted caller, a sibling's failure or an expired deadline
ends them as it ends any collector — and `signal` is never read. A rule keeps only its configuration and may answer concurrent
decisions; none reports an evaluation.

## Contract tests

[`../__tests__/rules/`](../__tests__/rules/) — one file per rule, the shared validation, and
[`collectors/`](../__tests__/rules/collectors/) for the two collectors; the purity suite and
its application named above; and the grouping the comparison rules rely on, end to end
through `evaluate()`, in
[`evaluate-with-rules.test.mts`](../../../../tests/integration/src/evaluate-with-rules.test.mts).
