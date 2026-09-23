# Collectors

Last updated: 2026-09-24

The built-in attribute collectors: the layer that reads the request and writes the
attributes the rules decide from.

## Responsibility

- **Role.** The attribute side of `@o3co/auth.policy-verifier.builtins`: core's
  `AttributePipeline` runs these collectors, and a deployment names them through
  `builtinCollectorsModule`. Each reads one request source — or only its configuration — and
  writes one slice of the `Attributes` map, under core's keys or the operator's own.
- **Owns.** The reading of each source and the narrowing of what is promoted. This is where
  claim vocabulary lives: `SubjectAttributes` is a bag of unknowns to core, and these
  collectors turn `sub`, `azp` and `scope` into `ATTR_USER_ID`, `ATTR_CLIENT_ID` and
  `ATTR_SCOPES` — the table in
  [AGENTS.md — Core Vocabulary Scope](../../../../AGENTS.md#core-vocabulary-scope).
- **Does not own.** The merge, the bounds or the decision (core's); the rules
  ([`../rules/`](../rules/README.md)); anything that needs I/O — a collector that reaches a
  store or an API is the consumer's to write,
  [docs/extending.md](../../../../docs/extending.md#writing-a-custom-attributecollector).
- **Why a separate module.** It is the split the engine rests on: collectors read the
  request, rules read `attrs` (o3co/auth.policy-verifier#251).

## Public contract

The collector classes and their config types are exported from [`../index.mts`](../index.mts)
and registered under their class names by [`../module.mts`](../module.mts). The `_`-prefixed
helpers are internal to the package. Options and examples:
[`../../README.md`](../../README.md#attribute-collectors).

## Inputs and outputs

- `subject` is verified: the authenticator established it from a credential it checked, so a
  claim promoted from it is on the deployment's side of the trust line. `requestContext` is
  the caller's: it arrives sealed and is unwrapped with `readUntrustedRequestContext` in one
  place, `RequestContextAttributeCollector` —
  [docs/extending.md — The trust boundary](../../../../docs/extending.md#the-trust-boundary-requestcontext-is-the-callers).
- None reads `headers`, `credential`, `resource` or `action`, and none does I/O, so `signal` is
  untouched.
- The output is one `Attributes` per collect, built fresh. Merging is core's: list keys
  concatenate across collectors, and a scalar written twice with different values denies the
  request — so a claim mapping onto `userId` beside `PayloadSubjectIdCollector` is a
  configuration to avoid.

## Dependencies

`@o3co/auth.policy-verifier.core` and files in this directory only — nothing from `../rules/`
or `../resource/`. The one edge into this directory from elsewhere in the package, besides
`../index.mts` and `../module.mts`, is `../rules/collectors/` importing `_claims.mts`.

## Invariants

- A reserved key is refused as a destination for caller-supplied data:
  `RequestContextAttributeCollector` refuses every key in core's registry, while
  `PayloadClaimAttributeCollector` lets a verified claim land on core's five and refuses the
  rest. The line is the trust boundary, not the source (`RESERVED_ATTRIBUTE_KEYS` in
  [`keys.mts`](../../../core/src/keys.mts)). Checked on the resolved key and refused at
  construction —
  [`RequestContextAttributeCollector.test.mts`](../__tests__/collectors/RequestContextAttributeCollector.test.mts),
  [`PayloadClaimAttributeCollector.test.mts`](../__tests__/collectors/PayloadClaimAttributeCollector.test.mts)
  and, across packages,
  [`reserved-attribute-keys.test.mts`](../../../../tests/integration/src/reserved-attribute-keys.test.mts).
- The claim collectors read the subject bag and never `requestContext`; the request-context
  collector reads nothing but `requestContext` (documented, not tested).
- Nothing undeclared, mistyped or inherited is promoted — the two mapping collectors' tests.
- A claim that is not a non-empty string is not an identity; a scope claim that is not a
  scope list asserts no capability —
  [`PayloadSubjectIdCollector.test.mts`](../__tests__/collectors/PayloadSubjectIdCollector.test.mts),
  [`PayloadScopeCollector.test.mts`](../__tests__/collectors/PayloadScopeCollector.test.mts).
- A collector holds nothing of the request past `collect` — no context, no `signal` — and
  writes nothing into its input (`subject` is read-only by type); documented, not tested.
  Configuration a collector keeps is its own copy, taken at construction, so a host that
  mutates its config afterwards changes nothing a later collect emits — for the static
  collectors, pinned by
  [`StaticPermissionCollector.test.mts`](../__tests__/collectors/StaticPermissionCollector.test.mts)
  and [`StaticRoleCollector.test.mts`](../__tests__/collectors/StaticRoleCollector.test.mts).

## Failure and lifecycle

- A collector that takes a declaration or a `claim` refuses a malformed one with an `Error`
  naming the collector and the field at construction, so a deployment that wrote it never
  serves a decision. `collect` does not throw on the shape of a claim or a field: what does
  not match is dropped.
- The pipeline's per-collector timeout and deadline are in force on every collect. These do
  no I/O and complete within any usable bound, but an already-aborted caller, a sibling's
  failure or a deadline that expires while one is queued ends it like any collector.
