# @o3co/auth.policy-verifier.builtins

Built-in attribute collectors, rule collectors, and resource parser for auth.policy-verifier.

**Runtime:** Runtime-agnostic. Loads in any modern JavaScript runtime that supports `BigInt` and `Map.groupBy` — Node.js 22+ (declared via `engines.node` so older Node installs are blocked at install time), modern browsers, Cloudflare Workers, Deno, Bun, Vercel Edge, etc. The `server` companion package remains Node-only.

## Install

```bash
npm install @o3co/auth.policy-verifier.builtins
```

## Attribute Collectors

All collectors implement `AttributeCollector`.

| Name | Reads from | Emits | Constructor args |
| --- | --- | --- | --- |
| `PayloadScopeCollector` | `payload.scope` (space-separated string) | `ATTR_SCOPES: string[]` | none |
| `PayloadSubjectIdCollector` | `payload.sub`, `payload.azp` | `ATTR_USER_ID`, `ATTR_CLIENT_ID` | none |
| `StaticPermissionCollector` | — | `ATTR_PERMISSIONS: string[]` | `{ permissions: string[] }` |
| `StaticRoleCollector` | — | `ATTR_ROLES: Role[]` | `{ roles: Role[] }` |

`StaticPermissionCollector` and `StaticRoleCollector` always emit the values supplied at construction time, regardless of request context.

### No built-in collector for `requestContext`

The engine does not ship a collector that expands `CollectorContext.requestContext` into attributes. The shape of `requestContext` is defined by each consuming project's transport/interceptor, so interpreting it is a project concern. Write a focused `AttributeCollector` for each field you need to promote — validate its shape there, and store it under a project-specific constant key. See [AGENTS.md — Core Vocabulary Scope](../../AGENTS.md#core-vocabulary-scope) for the rationale and a worked example.

## Rules

### HasPermission

```ts
new HasPermission(permission: string)
```

- `ruleType`: `"permission"`, `code`: `"no_permission"`
- Checks `ATTR_PERMISSIONS` (direct) and `ATTR_ROLES[].permissions` (via roles).
- Wildcard matching (case-insensitive):
  - `"*"` matches any permission.
  - `"foo*"` matches any permission with prefix `foo`.
  - `"*bar"` matches any permission with suffix `bar`.
  - `"foo*bar"` matches any permission starting with `foo` and ending with `bar`.

### HasScope

```ts
new HasScope(scope: string)
```

- `ruleType`: `"scope"`, `code`: `"invalid_scope"`
- Checks `ATTR_SCOPES`.
- A bare scope string `"resource"` in `ATTR_SCOPES` is normalized to `"read:resource"` before comparison.
- Matching is case-insensitive exact match after normalization.

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
- Default `ruleType`: `` `attr_literal_in:${a}:${type}:${count}:${hashPrefix}` `` — where `count` is the post-deduplication element count and `hashPrefix` is a 16-hex-character FNV-1a 64-bit hash over the deduplicated, sorted, stringified values. The hash is non-cryptographic but the 64-bit width makes accidental and adversarial collisions vanishingly unlikely for any realistic policy size; the package has no `node:*` dependency and loads in browser / edge runtimes. Two instances with the same `a` and logically equivalent `values` (duplicates and order do not matter) share the same `ruleType` and are OR-combined by the evaluator.
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

Both collectors take no constructor arguments.

## Resource Parser

### DotNotationResourceParser

Parses a dot-notation string into a `Resource`.

```ts
new DotNotationResourceParser()
```

Input format: `"<type>[:<id>].<type>[:<id>]..."`

Example: `"foo.bar:123"` → `{ raw: "foo.bar:123", resourceType: "foo_bar", resourceId: "123" }`

- Segments are split by `.`. Each segment may include `:id`.
- `resourceType` is the segment types joined with `_`.
- `resourceId` is the id of the last segment, if present.

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
| `ruleCollector` | `"ResourceActionScopeRuleCollector"` | `() => new ResourceActionScopeRuleCollector()` |
| `ruleCollector` | `"ResourceActionPermissionRuleCollector"` | `() => new ResourceActionPermissionRuleCollector()` |
| `resourceParser` | `"DotNotationResourceParser"` | `() => new DotNotationResourceParser()` |

## See Also

- [Extension guide (`docs/extending.md`)](../../docs/extending.md) — how to write custom `Rule` and `AttributeCollector` implementations; positioning of `builtins` as a basic set
- [`@o3co/auth.policy-verifier.core`](../core/README.md) — core interfaces and attribute constants
- [auth.policy-verifier root README](../../README.md) — full setup and configuration reference
