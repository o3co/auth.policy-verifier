# Collectors

Last updated: 2026-09-23

The built-in attribute collectors: the layer that reads the request and writes the
attributes the rules decide from.

## Responsibility

The attribute side of `@o3co/auth.policy-verifier.builtins`: core's `AttributePipeline` runs
these collectors (a deployment names them through `builtinCollectorsModule`), and they use
only core. They own the reading of one request source each and the narrowing of what is
promoted; they do not own the merge, the bounds or the decision (core's), the rules
([`../rules/`](../rules/)), or anything that needs I/O — a collector that reaches a store or
an API is the consumer's to write. They are a directory apart from `../rules/` because that
is the split the engine rests on: collectors read the request, rules read `attrs`
(o3co/auth.policy-verifier#251).

Each collector reads one source and writes one slice of the `Attributes` map, under core's
keys or the operator's own, narrowing what it promotes. This is where claim vocabulary lives
(#170): `SubjectAttributes` is a bag of unknowns to core, and these collectors turn `sub`,
`azp` and `scope` into `ATTR_USER_ID`, `ATTR_CLIENT_ID` and `ATTR_SCOPES` — the table in
[AGENTS.md — Core Vocabulary Scope](../../../../AGENTS.md#core-vocabulary-scope).

| Collector | Reads | Writes |
| --- | --- | --- |
| [`PayloadSubjectIdCollector`](PayloadSubjectIdCollector.mts) | `subject.sub`, `subject.azp` | `ATTR_USER_ID`, `ATTR_CLIENT_ID` — non-empty strings only |
| [`PayloadScopeCollector`](PayloadScopeCollector.mts) | `subject.scope`, or the configured `claim` (#219) | `ATTR_SCOPES` as a list — a space-delimited string or an array of strings; anything else is `[]` |
| [`PayloadClaimAttributeCollector`](PayloadClaimAttributeCollector.mts) | the declared claims of `subject` (#219) | the operator's keys, or core's five |
| [`RequestContextAttributeCollector`](RequestContextAttributeCollector.mts) | the declared fields of `requestContext` | the operator's keys; never a reserved one |
| [`StaticRoleCollector`](StaticRoleCollector.mts) | nothing of the request | `ATTR_ROLES`, from configuration |
| [`StaticPermissionCollector`](StaticPermissionCollector.mts) | nothing of the request | `ATTR_PERMISSIONS`, from configuration |

None reads `headers`, `credential`, `resource` or `action`, and none does I/O, so `signal` is
untouched. A collector that reaches a store or an API is the consumer's to write —
[docs/extending.md](../../../../docs/extending.md#writing-a-custom-attributecollector).

## Public contract

The six classes, exported from [`../index.mts`](../index.mts) with the config types of the
three that take one — `PayloadScopeCollectorConfig` (a `{ claim }`),
`PayloadClaimAttributeCollectorConfig` and `RequestContextAttributeCollectorConfig` (a
declaration each, with their `*Mapping` / `*Type` aliases, four in all); `PayloadSubjectIdCollector`
takes none, and the static collectors take a plain `{ roles }` / `{ permissions }` and export no
type. All six are registered under their class names by
[`../module.mts`](../module.mts). The declaration the
two mapping collectors share — `from`, `to`, `type` — is
[`_attributeMapping.mts`](_attributeMapping.mts); the scope-claim reading is
[`_claims.mts`](_claims.mts), which
[`../rules/collectors/ResourceActionScopeRuleCollector.mts`](../rules/collectors/ResourceActionScopeRuleCollector.mts)
also uses for the default claim name and its validation — so the two agree about which tokens
are scopeless only when given the same `claim`; each stores its own option, and nothing checks
that they match. Neither helper is exported.
Options and examples: [`../../README.md`](../../README.md#attribute-collectors).

## Inputs and outputs

- `subject` is verified: the authenticator established it from a credential it checked, so a
  claim promoted from it is on the deployment's side of the trust line. `requestContext` is
  the caller's: it arrives sealed and is unwrapped with `readUntrustedRequestContext` on the
  one line that reads it, in `RequestContextAttributeCollector.collect` —
  [docs/extending.md — The trust boundary](../../../../docs/extending.md#the-trust-boundary-requestcontext-is-the-callers).
- A mapping reads the exact key when the source has one, else a dot path over own properties
  only; a value is promoted only when it matches its declared type — `string`, `number`,
  `boolean`, `string[]`. An empty string is absent, and one empty entry drops a whole
  `string[]`; a `number` must be finite, so `NaN` and `±Infinity` are dropped here, while the
  rules layer's `requireNumber` in [`_sharedValidation.mts`](../rules/_sharedValidation.mts)
  accepts `Infinity` as a comparand. A promoted list is a copy (documented, not tested).
  Nothing undeclared is promoted.
- The output is one `Attributes` per collect, built fresh. Merging is core's: list keys
  concatenate across collectors, and a scalar written twice with different values denies the
  request — so
  a claim mapping onto `userId` beside `PayloadSubjectIdCollector` is a configuration to avoid.

## Dependencies

`@o3co/auth.policy-verifier.core` and the two `_` helpers here — nothing from `../rules/` or
`../resource/`. Imported by `../index.mts`, `../module.mts` and, for `_claims.mts` alone,
`../rules/collectors/`. The server package imports this package only in its tests; a
deployment names these collectors through `builtinCollectorsModule`.

## Invariants

- A reserved key is refused as a destination for caller-supplied data:
  `RequestContextAttributeCollector` refuses every key in core's registry — core's five and
  whatever a loaded package reserved, cedar's `request*` among them — while
  `PayloadClaimAttributeCollector` lets a verified claim land on core's five and refuses the
  rest. The line is the trust boundary, not the source (`RESERVED_ATTRIBUTE_KEYS` in
  [`keys.mts`](../../../core/src/keys.mts)). Checked on the resolved key, so `to` defaulting
  to `from` cannot slip past; refused at construction, naming the mapping's index and an
  unreserved rename — and the owner for another package's key, while a core key is called
  "the reserved core attribute" —
  [`RequestContextAttributeCollector.test.mts`](../__tests__/collectors/RequestContextAttributeCollector.test.mts),
  [`PayloadClaimAttributeCollector.test.mts`](../__tests__/collectors/PayloadClaimAttributeCollector.test.mts)
  and, across packages,
  [`reserved-attribute-keys.test.mts`](../../../../tests/integration/src/reserved-attribute-keys.test.mts).
- The claim collectors read the subject bag and never `requestContext` — the "reads the
  subject bag, never the request context" case of the claim collector's test; that the
  request-context collector reads nothing but `requestContext` is documented, not tested.
- Nothing undeclared, mistyped or inherited is promoted — the "promotes nothing a mapping did
  not declare" and "does not walk the prototype chain" cases of both mapping tests, "skips a
  value whose type does not match the declaration" in the request-context one and "skips a
  claim the token omitted, and a value whose type does not match" in the claim one.
- A claim that is not a non-empty string is not an identity; a scope claim that is not a
  scope list asserts no capability —
  [`PayloadSubjectIdCollector.test.mts`](../__tests__/collectors/PayloadSubjectIdCollector.test.mts),
  [`PayloadScopeCollector.test.mts`](../__tests__/collectors/PayloadScopeCollector.test.mts).
- A collector holds nothing of the request past `collect` — no context, no `signal` — and
  writes nothing into its input (`subject` is read-only by type). Documented, not tested:
  none of these keeps request-derived state between calls. Configuration they do keep — the
  mapping collectors a copy of their mappings, built at construction; the static collectors
  the list they were given (below). The rule-purity suite covers the rule side of this line.
  Holding the caller's *object* is covered under [Known issues](#known-issues).

## Failure and lifecycle

- The mapping and claim collectors refuse a malformed declaration — an empty `attributes`
  list, a bad `from` / `to` / `type`, a reserved destination, an empty or non-string `claim`
  — with an `Error` naming the collector and the field at construction, so a deployment that
  wrote it never serves a decision; their `collect` does not throw on the shape of a claim or
  a field: what does not match is dropped, and a request with no context yields an empty map.
- The static collectors validate nothing at construction: a `roles` / `permissions` that is
  missing or not iterable throws a `TypeError` on the first `collect` instead (documented, not
  tested). Each collect hands out a shallow copy of the configured list — the `Role` objects
  are shared (documented, not tested). The configured list itself is the caller's array, held
  by reference — see [Known issues](#known-issues).
- The pipeline's per-collector timeout and deadline are in force on every collect. These do no
  I/O and complete within any usable bound, but a bound is a bound: an already-aborted caller,
  a sibling's failure or a deadline that expires while one is queued ends it before or during
  `collect`, and a fan-out that has already ended makes any collector throw without running.

## Known issues

- [`StaticRoleCollector`](StaticRoleCollector.mts) and
  [`StaticPermissionCollector`](StaticPermissionCollector.mts) keep the array in their config
  by reference (`this.roles = config.roles`, `this.permissions = config.permissions`) and copy
  it only on each `collect`. A host that constructs one itself and then mutates the array it
  passed — or a `Role` in it — changes what every later collect emits, and so the decisions,
  with no validation. The comparison rules keep their config object the same way
  ([`../rules/README.md`](../rules/README.md#known-issues)); both fall under #255, which is to
  decide whether construction copies (or freezes) or the caller carries the obligation. The
  factories in [`../module.mts`](../module.mts) pass the config entry through unchanged, and
  the server's `createApp` hands them the entry from the config it was given — so the same
  holds for a host that mutates that config after boot. The mapping collectors and
  `PayloadScopeCollector` build what they keep at construction and are not affected.

## Contract tests

[`../__tests__/collectors/`](../__tests__/collectors/) — the four files named above, with
[`StaticRoleCollector.test.mts`](../__tests__/collectors/StaticRoleCollector.test.mts) and
[`StaticPermissionCollector.test.mts`](../__tests__/collectors/StaticPermissionCollector.test.mts)
— and [`../__tests__/module.test.mts`](../__tests__/module.test.mts) for the registrations. The
merge these collectors feed is pinned in core:
[`AttributePipeline.test.mts`](../../../core/src/__tests__/AttributePipeline.test.mts).
