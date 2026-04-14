# @o3co/auth.policy-verifier.core

Types, evaluation engine, and module infrastructure for auth.policy-verifier. This package defines the interfaces that collectors, rules, and modules implement.

## Install

```bash
npm install @o3co/auth.policy-verifier.core
```

## Public API

### evaluate

```typescript
function evaluate(attrs: Attributes, rules: Rule[]): Decision
```

Evaluates collected attributes against a set of rules. Rules are grouped by `ruleType`; within a group, any passing rule satisfies the group (OR); all groups must be satisfied for an allow decision (AND across groups). Returns `{ decision: "allow" }` or `{ decision: "deny"; code: string; message: string }`.

### AttributePipeline

```typescript
class AttributePipeline {
  constructor(collectors: AttributeCollector[])
  collect(context: CollectorContext): Promise<Attributes>
}
```

Runs all collectors in parallel and merges the results. Array values are concatenated; for all other types, the last writer wins.

### RulePipeline

```typescript
class RulePipeline {
  constructor(collectors: RuleCollector[])
  collect(context: CollectorContext): Promise<Rule[]>
}
```

Runs all collectors in parallel and flattens their results into a single array.

### Registry\<T\>

```typescript
class Registry<T> {
  register(name: string, instance: T): void
  get(name: string): T
  has(name: string): boolean
  entries(): [string, T][]
}
```

A named registry. `register` throws on duplicate names; `get` throws if the name is not found.

### Module / ModuleContext

```typescript
interface Module {
  name: string
  init(context: ModuleContext): Promise<void>
}

interface ModuleContext {
  pathResolver: PathResolver
  config: Record<string, unknown>
  attributeCollectorRegistry: Registry<AttributeCollectorFactory>
  ruleCollectorRegistry: Registry<RuleCollectorFactory>
  resourceParserRegistry: Registry<ResourceParserFactory>
}
```

A module registers collector and parser factories into the provided registries during `init`. Configuration is passed through `config`.

### Types

| Type | Description |
| --- | --- |
| `Resource` | `{ raw: string; resourceType: string; resourceId?: string }` — parsed resource |
| `ResourceParser` | `parse(raw: string): Resource` — converts a raw resource string into a `Resource` |
| `CollectorContext` | Input passed to every collector: `payload`, `resource`, `action`, optional `headers` and `requestContext` |
| `Attributes` | `Map<string, unknown>` — subject attribute bag |
| `AttributeCollector` | `collect(context: CollectorContext): Promise<Attributes>` |
| `Rule` | `{ ruleType: string; code: string; message: string; verify(attrs: Attributes): boolean }` |
| `RuleCollector` | `collect(context: CollectorContext): Promise<Rule[]>` |
| `Decision` | `{ decision: "allow" } \| { decision: "deny"; code: string; message: string }` |
| `Role` | `{ name: string; permissions: string[] }` |
| `VerifierPayload` | Decoded JWT claims: `sub`, `azp`, `scope`, `iss`, `aud`, `exp`, `iat`, `token`, `tokenType`, plus arbitrary extra claims |
| `PathResolver` | `(specifier: string) => string` — resolves module-relative paths |
| `AttributeCollectorFactory` | Factory function that produces an `AttributeCollector` from config |
| `RuleCollectorFactory` | Factory function that produces a `RuleCollector` from config |
| `ResourceParserFactory` | Factory function that produces a `ResourceParser` from config |

### Constants

| Constant | Value | Description |
| --- | --- | --- |
| `ATTR_SCOPES` | `"scopes"` | Attribute key for OAuth scopes |
| `ATTR_PERMISSIONS` | `"permissions"` | Attribute key for explicit permissions |
| `ATTR_ROLES` | `"roles"` | Attribute key for roles |
| `ATTR_USER_ID` | `"userId"` | Attribute key for the subject user ID |
| `ATTR_CLIENT_ID` | `"clientId"` | Attribute key for the client ID (`azp`) |
| `ATTR_CLIENT_IP` | `"clientIp"` | Attribute key for the client IP address |

## Usage Example

```typescript
import { AttributePipeline, RulePipeline, evaluate } from '@o3co/auth.policy-verifier.core'
import {
  PayloadScopeCollector,
  ResourceActionScopeRuleCollector,
  DotNotationResourceParser,
} from '@o3co/auth.policy-verifier.builtins'

const parser = new DotNotationResourceParser()
const resource = parser.parse('project:1')
const context = { payload: decodedJwt, resource, action: 'read' }

const attrs = await new AttributePipeline([new PayloadScopeCollector()]).collect(context)
const rules = await new RulePipeline([new ResourceActionScopeRuleCollector()]).collect(context)
const decision = evaluate(attrs, rules)
```

## Writing Custom Collectors

Implement `AttributeCollector` (or `RuleCollector`), wrap it in a `Module`, and register the factory via `ModuleContext`.

```typescript
// collectors/MyRoleCollector.mts
import type { Attributes, AttributeCollector, CollectorContext } from '@o3co/auth.policy-verifier.core'
import { ATTR_ROLES } from '@o3co/auth.policy-verifier.core'

export class MyRoleCollector implements AttributeCollector {
  constructor(private config: { endpointUrl: string }) {}

  async collect(context: CollectorContext): Promise<Attributes> {
    // fetch roles from your API
    return new Map([[ATTR_ROLES, roles]])
  }
}
```

```typescript
// modules/custom.mts
import type { Module } from '@o3co/auth.policy-verifier.core'
import { MyRoleCollector } from '../collectors/MyRoleCollector.mjs'

export const customModule: Module = {
  name: 'custom',
  async init(context) {
    context.attributeCollectorRegistry.register(
      'MyRoleCollector',
      (config) => new MyRoleCollector(config),
    )
  },
}
```

Pass `customModule` to `createApp` in the standalone entrypoint. See the root README for the full wiring example.

## See Also

- [Root README](../../README.md) — full setup, configuration, and server usage
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.md) — built-in collectors, rules, and resource parser
- [`@o3co/auth.policy-verifier.server`](../server/README.md) — Express HTTP server and `createApp`
