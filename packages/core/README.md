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
  constructor(collectors: AttributeCollector[], limits?: CollectorLimits)
  collect(request: CollectorRequest): Promise<Attributes>
}
```

Runs all collectors in parallel and merges the results. Array values are concatenated; for all other types, the last writer wins.

The fan-out is bounded — see [Collector limits](#collector-limits). `collect` takes a `CollectorRequest` (the request without a `signal`); the pipeline supplies each collector its own.

### RulePipeline

```typescript
class RulePipeline {
  constructor(collectors: RuleCollector[], limits?: CollectorLimits)
  collect(request: CollectorRequest): Promise<Rule[]>
}
```

Runs all collectors in parallel and flattens their results into a single array, under the same bounds as `AttributePipeline`.

### Collector limits

```typescript
interface CollectorLimits {
  collectorTimeoutMs?: number; // one collector's budget;      default 2000
  deadlineMs?: number;         // the whole fan-out, per pipeline; default 5000
  concurrency?: number;        // collectors in flight at once;    default 8
}
```

Collectors call databases and HTTP APIs, so a pipeline that ran them under a bare `Promise.all` had no way to stop waiting. Each collector is handed its own `AbortSignal` on `CollectorContext.signal` and its own budget; the wave gets a deadline; and only `concurrency` collectors run at once. Every default is applied when nothing is passed, so a pipeline constructed with no limits is still bounded. A limit that is not a positive integer is refused by the constructor (`RangeError`) rather than ignored — `concurrency: 0` would otherwise resolve with nothing collected.

**A bound that trips throws `CollectorTimeoutError`; it never resolves partially.** Partial attributes weaken a rule's inputs, and partial rules weaken the policy — an empty rule set is an allow under `{ onEmptyRuleSet: "allow" }`. There is no safe "answer with what we got" on an authorization path.

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
interface Module<C extends ModuleContext = ModuleContext> {
  name: string
  init(context: C): Promise<void>
}

interface ModuleContext {
  pathResolver: PathResolver
  config: Record<string, unknown>
  attributeCollectorRegistry: Registry<AttributeCollectorFactory>
  ruleCollectorRegistry: Registry<RuleCollectorFactory>
  resourceParserRegistry: Registry<ResourceParserFactory>
}
```

A module registers collector and parser factories into the provided registries during `init`. Configuration is passed through `config`. A host may initialize modules with a wider context: the default server's `ServerModuleContext` (in `@o3co/auth.policy-verifier.server`) extends this with a JWT key-resolver registry, and a module that needs it declares `Module<ServerModuleContext>`.

### Types

| Type | Description |
| --- | --- |
| `Resource` | `{ raw: string; resourceType: string; resourceId?: string }` — parsed resource |
| `ResourceParser` | `parse(raw: string): Resource` — converts a raw resource string into a `Resource`; throws `ResourceParseError` when the string is not in the syntax it parses |
| `ResourceParseError` | `Error` subclass carrying `raw` (the refused string) and `detail` (why). A **request** error, not a server error — the transport layer answers it 400-class. Exported as a class, so `instanceof` narrows it |
| `CollectorContext` | Input passed to every collector: `subject`, `resource`, `action`, `signal`, optional `headers` and `requestContext` |
| `CollectorRequest` | What a pipeline is handed: a `CollectorContext` without the per-collector `signal`, which the pipeline supplies. Its own optional `signal` is caller-side cancellation, linked into the pipeline's |
| `CollectorLimits` | `{ collectorTimeoutMs?, deadlineMs?, concurrency? }` — the bounds a pipeline runs its fan-out under. See [Collector limits](#collector-limits) |
| `CollectorTimeoutError` | `Error` subclass thrown when a collector overruns its budget or a fan-out overruns its deadline. Carries `pipeline`, `limit`, `timeoutMs` and (for a per-collector timeout) `collector`. **A deny, not a degradation** — the pipeline returns nothing at all |
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
| `SubjectAttributes` | `{ readonly [key: string]: unknown }` — verified attributes of the subject, populated by the transport. Core names no field; under the default server the keys are the verified JWT's claims (`sub`, `azp`, `scope`, …) plus `authScheme` (the `Authorization` scheme the token arrived under, not a claim) |
| `PathResolver` | `(specifier: string) => string` — resolves module-relative paths |
| `AttributeCollectorFactory` | Factory function that produces an `AttributeCollector` from config |
| `RuleCollectorFactory` | Factory function that produces a `RuleCollector` from config |
| `ResourceParserFactory` | Factory function that produces a `ResourceParser` from config |

`KeyResolver` / `KeyResolverFactory` are not core types: they are token-credential plumbing and live in `@o3co/auth.policy-verifier.server` (#170).

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
// `subject` is whatever your transport vouches for — the default server
// spreads verified JWT claims into it.
const context = { subject: verifiedClaims, resource, action: 'read' }

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
