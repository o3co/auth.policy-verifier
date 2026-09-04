# @o3co/auth.policy-verifier.builtins

Built-in attribute collectors, rule collectors, and resource parser for auth.policy-verifier.

**Runtime:** Server- and edge-side JavaScript runtimes that support `BigInt` and `Map.groupBy` — Node.js 22+ (declared via `engines.node` so older Node installs are blocked at install time), Cloudflare Workers, Vercel Edge, Deno, Bun. Browsers are out of scope by design: authorization decisions must be enforced server-side. The `server` companion package remains Node-only.

## Install

```bash
npm install @o3co/auth.policy-verifier.builtins
```

## Attribute Collectors

All collectors implement `AttributeCollector`.

| Name | Reads from | Emits | Constructor args |
| --- | --- | --- | --- |
| `PayloadScopeCollector` | `subject.scope` (space-separated string) | `ATTR_SCOPES: string[]` | none |
| `PayloadSubjectIdCollector` | `subject.sub`, `subject.azp` | `ATTR_USER_ID`, `ATTR_CLIENT_ID` | none |
| `StaticPermissionCollector` | — | `ATTR_PERMISSIONS: string[]` | `{ permissions: string[] }` |
| `StaticRoleCollector` | — | `ATTR_ROLES: Role[]` | `{ roles: Role[] }` |
| `RequestContextAttributeCollector` | declared fields of `requestContext` | the operator's own keys | `{ attributes: Mapping[] }` |

`StaticPermissionCollector` and `StaticRoleCollector` always emit the values supplied at construction time, regardless of request context.

### RequestContextAttributeCollector

Promotes declared fields of `CollectorContext.requestContext` into attributes:

```hocon
{ collector = "RequestContextAttributeCollector"
  attributes = [
    { from = "tenant.id", to = "tenantId" }     # dot path; `to` defaults to `from`
    { from = "groups", type = "string[]" }
  ] }
```

Each mapping is `{ from: string; to?: string; type?: "string" | "number" | "boolean" | "string[]" }`, `type` defaulting to `"string"`. A malformed mapping throws at construction; an unusable *value* does not — `requestContext` is caller-supplied request data, so a field that is missing, empty, or not of its declared type is simply not promoted.

The declaration is the trust boundary — this collector is the ready-made way to stay on the right side of the one described in [docs/extending.md](../../docs/extending.md#the-trust-boundary-requestcontext-is-the-callers). `requestContext` is free-form and unvalidated, so **nothing undeclared becomes an attribute** and a configured dot path traverses own properties only (`constructor.name` reads nothing). This collector invents no vocabulary of its own: the operator names both the fields and the keys, which is what keeps [AGENTS.md — Core Vocabulary Scope](../../AGENTS.md#core-vocabulary-scope) intact while still shipping something usable. For anything beyond read-check-write — deriving a value, calling out to a store — write a focused project-side `AttributeCollector` as that section describes.

#### The core vocabulary is not a valid destination

A mapping's `to` may not name one of core's `ATTR_*` keys — `scopes`, `permissions`, `roles`, `userId`, `clientId` (exported as `RESERVED_ATTRIBUTE_KEYS`). Naming one is a **configuration error, refused at construction**, so a deployment that writes it fails at boot rather than on the first request:

```hocon
# refused at boot
{ from = "groups", to = "scopes" }

# fine — the field may be called anything; only the attribute key is reserved
{ from = "groups", to = "requestGroups", type = "string[]" }
{ from = "scopes", to = "requestedScopes", type = "string[]" }
```

`context` is the caller's, and those five keys are the engine's. Under the default server `scopes`, `userId` and `clientId` are read out of the **signature-verified token**, and `permissions` / `roles` carry the entitlements the builtin rules decide from — so the two sides of that mapping carry entirely different trust, and the request body must not join the token in one bucket.

What makes it worth refusing rather than documenting is the merge: `AttributePipeline` **unions** array-valued attributes across collectors. A mapping onto `scopes` therefore does not overwrite what `PayloadScopeCollector` produced and lose an argument with it — it *extends* it. A caller sending `context.groups = ["admin:write"]` would be authorized for a scope its token never carried, and nothing in the decision, the logs or the metrics would tell that apart from an issuer that granted it. See `AttributePipeline`'s merge doc comment.

## Rules

### HasPermission

```ts
new HasPermission(permission: string)
```

- `ruleType`: `"permission"`, `code`: `"no_permission"`
- Checks `ATTR_PERMISSIONS` (direct) and `ATTR_ROLES[].permissions` (via roles).
- Matching is **exact and case-sensitive** — the same discipline `HasScope` applies to scopes and `DotNotationResourceParser` applies to resources: compare what was written, never a normalized guess at what was meant. The parser preserves case, so `Project:1.perm:read` and `project:1.perm:read` are different permissions, exactly as `Project:1` and `project:1` are different resources to a scope rule.
- Wildcards in a **granted** permission are honoured — written match structure, not normalization; the literal halves around the `*` still compare exactly:
  - `"*"` matches any permission.
  - `"foo*"` matches any permission with prefix `foo`.
  - `"*bar"` matches any permission with suffix `bar`.
  - `"foo*bar"` matches any permission starting with `foo` and ending with `bar`.
  - More than one `*` in a granted permission never matches (rejecting beats silently over-granting).

### HasScope

```ts
new HasScope(scope: string, options?: { allowBareScopeRewrite?: boolean })
```

- `ruleType`: `"scope"`, `code`: `"invalid_scope"`
- Checks `ATTR_SCOPES`.
- Matching is **exact and case-sensitive**. OAuth 2.0 scope values are case-sensitive opaque strings ([RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3)), so `read:PROJECT` does not satisfy `read:project`.
- A scope containing more than one `:` is a value in its own right — nothing is split off at the second `:`. `read:project:restricted` does not satisfy `read:project` (a deliberately narrowed grant must not collapse into the broader one), and `read:project` does not satisfy `read:project:restricted`.
- `allowBareScopeRewrite` (default `false`) opts in to treating a bare granted scope `"resource"` as `"read:resource"` as well as literally. Only a scope with **no** `:` is ever rewritten; `"project:restricted"` is left alone, because which segment is the action is unknowable and guessing over-grants. Leave it off unless your issuer emits bare resource names.
- Non-string entries in `ATTR_SCOPES` never match and never throw.

### AttrMatchRule

**Deprecated.** Use [`AttrPairEqual`](#attrpairequal) instead. `AttrMatchRule` is kept as a thin wrapper class that extends `AttrPairEqual` and preserves the legacy `ruleType` (`attr_match:${a}:${b}`) and legacy `message` wording for backward compatibility. The type `AttrMatchRuleConfig` is a type alias of `AttrPairEqualConfig`. It will be removed in a future major version.

```ts
new AttrMatchRule({ a: string, b: string, group?: string })
```

- `code`: `"attr_mismatch"`.
- Passes when `attrs.get(a)` and `attrs.get(b)` are both non-empty strings and equal. Any other case returns `false` (fail closed).
- Pure predicate — does not read `CollectorContext`. Consuming projects provide the two values to compare through upstream `AttributeCollector`s and wire the rule through their own `RuleCollector`.
- `ruleType` defaults to `"attr_match:${a}:${b}"`. The evaluator ORs rules within a `ruleType` and ANDs across different `ruleType`s, so the default ensures two independent comparisons are AND-combined (required together). Pass `group` explicitly when you want two comparisons to be OR-combined (for example, "identify by DID or by email") — both rules then share the provided `group` as their `ruleType`.

## Attribute Comparison Rules

The attribute comparison rules form a 2 × 5 matrix over two axes: **family** (Literal vs. Pair) and **operator** (Equal, NotEqual, In, NotIn, Compare).

- **Literal** rules compare a single named attribute against a static value (or set of values) supplied at construction time.
- **Pair** rules compare two named attributes resolved from the `Attributes` map at evaluation time.
- `In` / `NotIn` variants exist for the Literal family only. A pair-over-set operation does not generalize cleanly to a finite list, so `AttrPairIn` / `AttrPairNotIn` are intentionally absent.

| Family  | Equal              | NotEqual              | In              | NotIn              | Compare              |
| ------- | ------------------ | --------------------- | --------------- | ------------------ | -------------------- |
| Literal | `AttrLiteralEqual` | `AttrLiteralNotEqual` | `AttrLiteralIn` | `AttrLiteralNotIn` | `AttrLiteralCompare` |
| Pair    | `AttrPairEqual`    | `AttrPairNotEqual`    | —               | —                  | `AttrPairCompare`    |

### AttrLiteralEqual

```ts
new AttrLiteralEqual({ a: string, v: string | number | boolean, group?: string })
```

- `code`: `"attr_not_equal"`.
- Default `ruleType`: `` `attr_literal_equal:${a}:${typeof v}:${String(v)}` ``. The `typeof v` segment prevents silent collisions between distinct-type literals that stringify the same way (e.g. `true` vs `"true"`).
- Passes when `attrs.get(a)` is the same type and strictly equal to `v`. No type coercion.

### AttrLiteralNotEqual

```ts
new AttrLiteralNotEqual({ a: string, v: string | number | boolean, group?: string })
```

- `code`: `"attr_equal"`.
- Default `ruleType`: `` `attr_literal_not_equal:${a}:${typeof v}:${String(v)}` ``. The `typeof v` segment prevents silent collisions between distinct-type literals (same rationale as `AttrLiteralEqual`).
- Passes when `attrs.get(a)` is the same type as `v` and strictly not equal to it. Missing or wrong-type attributes return `false` (safe-deny).

### AttrLiteralIn

```ts
new AttrLiteralIn({ a: string, values: (string | number | boolean)[], group?: string })
```

- `code`: `"attr_not_in_set"`.
- Default `ruleType`: `` `attr_literal_in:${a}:${type}:${count}:${hashPrefix}` `` — where `count` is the post-deduplication element count and `hashPrefix` is a 16-hex-character FNV-1a 64-bit hash over the deduplicated, sorted, stringified values. The hash is non-cryptographic but the 64-bit width makes accidental and adversarial collisions vanishingly unlikely for any realistic policy size; the package has no `node:*` dependency and loads in any supported server/edge runtime (see "Runtime" above). Two instances with the same `a` and logically equivalent `values` (duplicates and order do not matter) share the same `ruleType` and are OR-combined by the evaluator.
- `values` must be a non-empty, homogeneous array (`string[]`, `number[]`, or `boolean[]`). Passes when `attrs.get(a)` is in the set. Duplicate elements in `values` are ignored (the rule uses `Set` semantics internally).

### AttrLiteralNotIn

```ts
new AttrLiteralNotIn({ a: string, values: (string | number | boolean)[], group?: string })
```

- `code`: `"attr_in_set"`.
- Default `ruleType`: `` `attr_literal_not_in:${a}:${type}:${count}:${hashPrefix}` `` — same stable, deduplication-aware hash scheme as `AttrLiteralIn`.
- `values` must be a non-empty, homogeneous array. Passes when `attrs.get(a)` is NOT in the set. Duplicate elements in `values` are ignored.

### AttrLiteralCompare

```ts
new AttrLiteralCompare({ a: string, op: "lt" | "le" | "gt" | "ge", v: number, group?: string })
```

- `code`: `"attr_compare_violated"`.
- Default `ruleType`: `` `attr_literal_compare:${a}:${op}:${String(v)}` ``.
- Passes when `attrs.get(a)` is a number satisfying `a op v`. NaN as `v` is rejected at construction time. NaN attributes always return `false`.

### AttrPairEqual

```ts
new AttrPairEqual({ a: string, b: string, group?: string })
```

- `code`: `"attr_mismatch"`.
- Default `ruleType`: `` `attr_pair_equal:${a}:${b}` ``.
- Passes when both `attrs.get(a)` and `attrs.get(b)` are non-empty strings and strictly equal. This is the successor to the deprecated `AttrMatchRule`.

### AttrPairNotEqual

```ts
new AttrPairNotEqual({ a: string, b: string, group?: string })
```

- `code`: `"attr_match"`.
- Default `ruleType`: `` `attr_pair_not_equal:${a}:${b}` ``.
- Passes when both `attrs.get(a)` and `attrs.get(b)` are non-empty strings and strictly not equal. Missing, empty, or non-string attributes return `false` (safe-deny).

### AttrPairCompare

```ts
new AttrPairCompare({ a: string, op: "lt" | "le" | "gt" | "ge", b: string, group?: string })
```

- `code`: `"attr_compare_violated"`.
- Default `ruleType`: `` `attr_pair_compare:${a}:${op}:${b}` ``.
- Passes when both `attrs.get(a)` and `attrs.get(b)` are numbers satisfying `a op b`. NaN on either side returns `false` (JS comparison semantics).

### Grouping: AND by default, `group` for OR

All attribute comparison rules follow the same grouping semantics described for `AttrMatchRule` above. By default, each rule's `ruleType` is derived from its distinguishing parameters so that distinct requirements are AND-combined by the evaluator. Pass the same `group` string to two rules to give them the same `ruleType` — the evaluator then OR-combines them (either condition satisfies the requirement).

## Rule Collectors

| Name | Derives permission/scope | Returns |
| --- | --- | --- |
| `ResourceActionPermissionRuleCollector` | `"<resource.raw>.perm:<action>"` | `[HasPermission(...)]` |
| `ResourceActionScopeRuleCollector` | `"<action>:<resource.resourceType>"` | `[HasScope(...)]` |

`ResourceActionPermissionRuleCollector` takes no constructor arguments.
`ResourceActionScopeRuleCollector` accepts `{ scopeless?: "deny" | "skip", allowBareScopeRewrite?: boolean }`.

- `scopeless` (default `"deny"`): it emits the `HasScope` rule for every request, so a token carrying no `scope`
  claim fails it. `"skip"` emits no rule for a scopeless token — only use it in a pipeline where another rule
  group authorizes the request, since a request that collects no rule at all is denied.
- `allowBareScopeRewrite` (default `false`): forwarded to [`HasScope`](#hasscope). Set it to `true` only if your
  issuer emits bare resource names (`project`) rather than `{action}:{resourceType}` scopes (`read:project`).

## Resource Parser

### DotNotationResourceParser

Parses a dot-notation string into a `Resource`.

```ts
new DotNotationResourceParser()
```

Grammar:

```text
resource = segment *( "." segment )
segment  = type [ ":" id ]
type     = 1*tchar
id       = 1*tchar
tchar    = %x21 / %x23-2D / %x2F-39 / %x3B-5B / %x5D-7E
           ; RFC 6749 NQCHAR less "." and ":"
           ; i.e. printable ASCII except space, `"`, `\`, `.` and `:`
```

Example: `"foo.bar:123"` → `{ raw: "foo.bar:123", resourceType: "foo.bar", resourceId: "123" }`

- Segments are split by `.`. Each segment may include `:id`.
- `resourceType` is the segment types joined with `.` — the separator is preserved, not rewritten.
- `resourceId` is the id of the last segment, if present.
- `raw` is the input verbatim.

Anything the grammar does not accept raises `ResourceParseError`
(from `@o3co/auth.policy-verifier.core`); the parser never repairs its input. The server answers
such a request `400 invalid_request`, not a decision. Refused, among others:

| Input | Why |
| --- | --- |
| `""`, `a..b`, `.a`, `a.` | an empty segment — every segment needs a type |
| `a:`, `:1` | an empty type or id |
| `a:1:2` | more than one `:` in a segment — the tail is refused, not truncated away |
| `  a:1  `, `a : 1` | whitespace — it is refused, not trimmed |
| `プロジェクト`, `a"b`, `a\b` | a character no OAuth scope value may carry |

`resourceType` is the authorization namespace: `ResourceActionScopeRuleCollector` turns it into the
`{action}:{resourceType}` scope that must be granted. Two distinct resources that parse to the same
type are therefore authorized identically, so the grammar is built to make that impossible —
`.` is reserved as the separator, which keeps the nested type `a.b` distinct from the flat type
literally named `a_b` (both were `a_b` before). This is the same principle
[`HasScope`](#hasscope) applies to scope values: compare what was written, never a normalized guess
at what was meant.

An id that needs `.`, `:` or a character outside the set must be encoded by the caller
(percent-encoding round-trips through this grammar) or handled by a `ResourceParser` written for
that syntax.

## builtinCollectorsModule

`builtinCollectorsModule` is a `Module` (name: `"builtin-collectors"`) that registers all built-in implementations into their respective registries.

```ts
import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
```

| Registry | Name | Factory |
| --- | --- | --- |
| `attributeCollector` | `"PayloadScopeCollector"` | `() => new PayloadScopeCollector()` |
| `attributeCollector` | `"PayloadSubjectIdCollector"` | `() => new PayloadSubjectIdCollector()` |
| `attributeCollector` | `"StaticPermissionCollector"` | `(config) => new StaticPermissionCollector(config)` |
| `attributeCollector` | `"StaticRoleCollector"` | `(config) => new StaticRoleCollector(config)` |
| `attributeCollector` | `"RequestContextAttributeCollector"` | `(config) => new RequestContextAttributeCollector(config)` |
| `ruleCollector` | `"ResourceActionScopeRuleCollector"` | `(config) => new ResourceActionScopeRuleCollector(config)` |
| `ruleCollector` | `"ResourceActionPermissionRuleCollector"` | `() => new ResourceActionPermissionRuleCollector()` |
| `resourceParser` | `"DotNotationResourceParser"` | `() => new DotNotationResourceParser()` |

## See Also

- [Extension guide (`docs/extending.md`)](../../docs/extending.md) — how to write custom `Rule` and `AttributeCollector` implementations; positioning of `builtins` as a basic set
- [`@o3co/auth.policy-verifier.core`](../core/README.md) — core interfaces and attribute constants
- [auth.policy-verifier root README](../../README.md) — full setup and configuration reference
