# @o3co/auth.policy-verifier.core

Types, evaluation engine, and module infrastructure for auth.policy-verifier. This package defines the interfaces that collectors, rules, and modules implement.

**Runtime:** Server- and edge-side JavaScript runtimes that support `Map.groupBy` — Node.js 22+ (declared via `engines.node` so older Node installs are blocked at install time), Cloudflare Workers, Vercel Edge, Deno, Bun. Browsers are out of scope by design: authorization decisions must be enforced server-side. The `server` companion package remains Node-only.

## Install

```bash
npm install @o3co/auth.policy-verifier.core
```

## Public API

### evaluate

```typescript
interface EvaluateOptions {
  /** Decision for an empty rule set. Defaults to "deny". */
  onEmptyRuleSet?: "deny" | "allow"
}

function evaluate(attrs: Attributes, rules: Rule[], options?: EvaluateOptions): Decision
```

Evaluates collected attributes against a set of rules. Rules are grouped by `ruleType`; within a group, any passing rule satisfies the group (OR); all groups must be satisfied for an allow decision (AND across groups). Returns `{ decision: "allow"; reason }` or `{ decision: "deny"; code: string; message: string; reason }`.

An **empty rule set is denied** (`code: "no_applicable_rule"`): a request no rule spoke to was never authorized. Pass `{ onEmptyRuleSet: "allow" }` as the third argument to opt a deployment out of that default.

Every decision carries a structured `reason`: `reason.groups` lists each rule group in evaluation order with `passed` and `evaluated` — the rules that group actually ran, in order. A failing group ran every alternative, so `evaluated` lists them all; a passing group is an OR and stops at its first passing rule, so `evaluated` holds the alternatives that were tried and failed followed by that rule, and `satisfiedBy` (present only on a passing group) names it as the one that decided. All groups are evaluated, including groups after the first failing one, because stopping early cannot report which of the rest would also have failed. The `code` / `message` on a deny still come from the first failing group.

An **empty rule set is denied** (`code: "no_applicable_rule"`): a request no rule spoke to was never authorized. Pass `{ onEmptyRuleSet: "allow" }` as the third argument to opt a deployment out of that default.

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
  keyResolverRegistry: Registry<KeyResolverFactory>
}
```

A module registers collector, parser, and key resolver factories into the provided registries during `init`. Configuration is passed through `config`.

### Types

| Type | Description |
| --- | --- |
| `Resource` | `{ raw: string; resourceType: string; resourceId?: string }` — parsed resource |
| `ResourceParser` | `parse(raw: string): Resource` — converts a raw resource string into a `Resource`; throws `ResourceParseError` when the string is not in the syntax it parses |
| `ResourceParseError` | `Error` subclass carrying `raw` (the refused string) and `detail` (why). A **request** error, not a server error — the transport layer answers it 400-class. Exported as a class, so `instanceof` narrows it |
| `CollectorContext` | Input passed to every collector: `payload`, `resource`, `action`, optional `headers` and `requestContext` |
| `UntrustedRequestContext` | The type of `requestContext` — the caller's own data, sealed so it takes an explicit `readUntrustedRequestContext(...)` to read. `markUntrustedRequestContext(...)` mints one at the transport boundary. See [docs/extending.md — The trust boundary](../../docs/extending.md#the-trust-boundary-requestcontext-is-the-callers) |
| `Attributes` | `Map<string, unknown>` — subject attribute bag. Mutable: collectors build one, and `AttributePipeline` merges them |
| `ReadonlyAttributes` | `ReadonlyMap<string, unknown>` — the view a rule is judged against. The evaluator hands the same live map to every rule, so a rule that wrote into it would change the inputs of every group after it |
| `AttributeCollector` | `collect(context: CollectorContext): Promise<Attributes>` |
| `Rule` | `{ ruleType: string; code: string; message: string; verify(attrs: ReadonlyAttributes): boolean }` — `verify` must be a deterministic, side-effect-free function of `attrs`. See [AGENTS.md — Collector / Rule / Attribute Contract](../../AGENTS.md#collector--rule--attribute-contract) |
| `RuleCollector` | `collect(context: CollectorContext): Promise<Rule[]>` |
| `Decision` | `{ decision: "allow"; reason: DecisionReason } \| { decision: "deny"; code: string; message: string; reason: DecisionReason }` |
| `DecisionReason` | `{ groups: RuleGroupOutcome[] }` |
| `RuleGroupOutcome` | `{ ruleType: string; passed: true; evaluated: RuleOutcome[]; satisfiedBy: RuleOutcome } \| { ruleType: string; passed: false; evaluated: RuleOutcome[] }` — `evaluated` is every rule that ran, in order; `satisfiedBy` names the rule that satisfied a passing group |
| `RuleOutcome` | `{ code: string; message: string; passed: boolean }` |
| `Role` | `{ name: string; permissions: string[] }` |
| `VerifierPayload` | Decoded JWT claims: `sub`, `azp`, `scope`, `iss`, `aud`, `exp`, `iat`, `token`, `tokenType`, plus arbitrary extra claims |
| `PathResolver` | `(specifier: string) => string` — resolves module-relative paths |
| `AttributeCollectorFactory` | Factory function that produces an `AttributeCollector` from config |
| `RuleCollectorFactory` | Factory function that produces a `RuleCollector` from config |
| `ResourceParserFactory` | Factory function that produces a `ResourceParser` from config |
| `KeyResolver` | `{ key: unknown; algorithms: string[] }` — abstract JWT key material; concrete `key` type is owned by the consuming JWT library (jose in the default server) |
| `KeyResolverFactory` | Factory function `(config: any) => Promise<KeyResolver>` that produces a `KeyResolver` for a given algorithm |

### Constants

The `ATTR_*` constants are limited to well-known OAuth 2.0 / OIDC and RBAC vocabulary: concepts every consumer of the ABAC engine shares (JWT claims, OAuth scopes, RBAC roles and permissions). Domain-specific attribute keys belong to the consuming service, not to core. Consumers declare their own constants and read/write the same `Attributes` map.

| Constant | Value | Description |
| --- | --- | --- |
| `ATTR_SCOPES` | `"scopes"` | Attribute key for OAuth scopes |
| `ATTR_PERMISSIONS` | `"permissions"` | Attribute key for explicit permissions |
| `ATTR_ROLES` | `"roles"` | Attribute key for roles |
| `ATTR_USER_ID` | `"userId"` | Attribute key for the subject user ID (JWT `sub`) |
| `ATTR_CLIENT_ID` | `"clientId"` | Attribute key for the client ID (JWT `azp`) |

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

For the full extension guide — including how to author custom `Rule` implementations, `ruleType` grouping semantics, and guidance on when to write custom logic vs. use [`@o3co/auth.policy-verifier.builtins`](../builtins/README.md) — see [`docs/extending.md`](../../docs/extending.md).

## See Also

- [Root README](../../README.md) — full setup, configuration, and server usage
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.md) — built-in collectors, rules, and resource parser
- [`@o3co/auth.policy-verifier.server`](../server/README.md) — Express HTTP server and `createApp`
