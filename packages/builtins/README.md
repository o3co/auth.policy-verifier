# @o3co/auth.policy-verifier.builtins

Built-in attribute collectors, rule collectors, and resource parser for auth.policy-verifier.

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
| `RequestContextCollector` | `context.requestContext.ip` | `ATTR_CLIENT_IP` | none |
| `StaticPermissionCollector` | — | `ATTR_PERMISSIONS: string[]` | `{ permissions: string[] }` |
| `StaticRoleCollector` | — | `ATTR_ROLES: Role[]` | `{ roles: Role[] }` |

`StaticPermissionCollector` and `StaticRoleCollector` always emit the values supplied at construction time, regardless of request context.

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
| `attributeCollector` | `"RequestContextCollector"` | `() => new RequestContextCollector()` |
| `attributeCollector` | `"StaticPermissionCollector"` | `(config) => new StaticPermissionCollector(config)` |
| `attributeCollector` | `"StaticRoleCollector"` | `(config) => new StaticRoleCollector(config)` |
| `ruleCollector` | `"ResourceActionScopeRuleCollector"` | `() => new ResourceActionScopeRuleCollector()` |
| `ruleCollector` | `"ResourceActionPermissionRuleCollector"` | `() => new ResourceActionPermissionRuleCollector()` |
| `resourceParser` | `"DotNotationResourceParser"` | `() => new DotNotationResourceParser()` |

## See Also

- [`@o3co/auth.policy-verifier.core`](../core/README.md) — core interfaces and attribute constants
- [auth.policy-verifier root README](../../README.md) — full setup and configuration reference
