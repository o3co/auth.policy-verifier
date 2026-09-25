# @o3co/auth.policy-verifier.core

Last updated: 2026-09-25

Types, evaluation engine, and module infrastructure for auth.policy-verifier. This package defines the interfaces that collectors, rules, and modules implement.

**Runtime:** Server- and edge-side JavaScript runtimes that support `Map.groupBy` — Node.js 22+ (declared via `engines.node` so older Node installs are blocked at install time), Cloudflare Workers, Vercel Edge, Deno, Bun. Browsers are out of scope by design: authorization decisions must be enforced server-side. The `server` companion package remains Node-only.

## Responsibility

The bottom layer of auth.policy-verifier: `builtins`, `cedar` and `server` depend on it, and it
depends on nothing (`package.json` declares no `dependencies`).

- **Owns** the contract a decision is made in — `CollectorContext`, `Attributes`, the collector
  and rule interfaces, `Decision` — and the steps that reach one: the bounded collector
  pipelines and `evaluate()`, with their semantics (OR within a `ruleType` group, AND across,
  default deny, fail-closed bounds), errors and failure attribution; the five `ATTR_*` keys and
  the attribute-key reservation registry; the `Logger` port; the `Module` / `Registry` shape a
  composition is built from.
- **Does not own** a transport (HTTP is `server`'s), credential verification (the subject
  arrives established; `KeyResolver` and the token authenticator are `server`'s), a policy
  engine (`AsyncRule` is the seam one sits behind; `cedar` is one), the concrete collectors and
  rules (`builtins` or the consumer), domain attribute vocabulary, or configuration — every
  bound reaches it as a number.
- **Why a separate package:** it is the contract every collector, rule and module is written
  against, so it carries no transport, credential or policy-engine dependency with it and runs
  on the edge runtimes listed above while `server` stays Node-only; a deployment can replace
  the server or the builtins and keep it.

Responsibility, role and invariants of the source directory: [`src/README.md`](src/README.md).

## Install

```bash
npm install @o3co/auth.policy-verifier.core
```

## Public API

Everything the package exports is listed in [`src/index.mts`](src/index.mts). Each entry below links the file that defines it; the doc comments there are the reference for names and signatures, and this section says what each piece does.

### evaluate

`evaluate(attrs, rules, options?)` and its `EvaluateOptions` are defined in [`src/evaluate.mts`](src/evaluate.mts). The options are `onEmptyRuleSet` (`"deny"` by default), `ruleTimeoutMs` and `evaluateDeadlineMs` (the asynchronous-rule budgets, defaulting to `DEFAULT_RULE_TIMEOUT_MS` and `DEFAULT_EVALUATE_DEADLINE_MS` from [`src/collectorLimits.mts`](src/collectorLimits.mts), 2000 and 5000 ms), the caller's `signal`, and a `failures` [`FailureRecord`](#failurerecord).

Evaluates collected attributes against a set of rules. Rules are grouped by `ruleType`; within a group, any passing rule satisfies the group (OR); all groups must be satisfied for an allow decision (AND across groups). It resolves to a `Decision`: an allow with a `reason`, or a deny with a `code`, a `message` and a `reason`.

An **empty rule set is denied** (`code: "no_applicable_rule"`): a request no rule spoke to was never authorized. Pass `{ onEmptyRuleSet: "allow" }` as the third argument to opt a deployment out of that default.

Every decision carries a structured `reason`: `reason.groups` lists each rule group in evaluation order with `passed` and `evaluated` — the rules that group actually ran, in order. A failing group ran every alternative, so `evaluated` lists them all; a passing group is an OR and stops at its first passing rule, so `evaluated` holds the alternatives that were tried and failed followed by that rule, and `satisfiedBy` (present only on a passing group) names it as the one that decided. All groups are evaluated, including groups after the first failing one, because stopping early cannot report which of the rest would also have failed. The `code` / `message` on a deny still come from the first failing group.

The rule list may carry either kind of rule (#225): a synchronous `Rule` is asked through `verify`, an `AsyncRule` is awaited through `decide` under `ruleTimeoutMs`, one at a time in collection order, and alternatives after a pass never run whichever kind they are. `evaluate` is asynchronous for that reason alone — a list of synchronous rules answers in the same turn. It rejects with `RuleTimeoutError` when an asynchronous rule overruns its budget, or the rules together overrun `evaluateDeadlineMs` (`limit: "rule"` or `"deadline"`; a deny for the transport, never a pass), with the caller's abort reason when `signal` aborts, and with whatever a rule threw or rejected with — unchanged, with the rule recorded in `failures` when a [`FailureRecord`](#failurerecord) was handed in.

### AttributePipeline

Defined in [`src/AttributePipeline.mts`](src/AttributePipeline.mts). Constructed from a list of `AttributeCollector`s and optional [collector limits](#collector-limits); `collect(request, { failures }?)` resolves to the merged `Attributes`.

Runs the collectors concurrently — up to `CollectorLimits.concurrency` at a time, the rest queued behind them — and merges the results. Array values are concatenated in collector order; any other value may be written once, or written again with the same value — two collectors writing *different* values to one key throw `AttributeConflictError`, which the server answers as a deny (#174).

The fan-out is bounded — see [Collector limits](#collector-limits). `collect` takes a `CollectorRequest` (the request without a `signal`); the pipeline supplies each collector its own.

### RulePipeline

Defined in [`src/RulePipeline.mts`](src/RulePipeline.mts). Constructed from a list of `RuleCollector`s and optional [collector limits](#collector-limits); `collect(request, { failures }?)` resolves to one flat rule list.

Runs the collectors concurrently under the same bounds as `AttributePipeline`, `CollectorLimits.concurrency` included, and flattens their results into a single array. A collector may return synchronous `Rule`s, asynchronous `AsyncRule`s, or both.

### Collector limits

`CollectorLimits` and its defaults are defined in [`src/collectorLimits.mts`](src/collectorLimits.mts). It carries three optional bounds: `collectorTimeoutMs` (one collector's budget, default 2000 ms), `deadlineMs` (the whole fan-out of one pipeline, default 5000 ms) and `concurrency` (collectors in flight at once, default 8).

Collectors call databases and HTTP APIs, so a pipeline that ran them under a bare `Promise.all` had no way to stop waiting. Each collector is handed its own `AbortSignal` on `CollectorContext.signal` and its own budget; the wave gets a deadline; and only `concurrency` collectors run at once. Every default is applied when nothing is passed, so a pipeline constructed with no limits is still bounded. A limit that is not a positive integer, or a millisecond budget above what a timer can hold (`MAX_TIMER_MS`), is refused by the constructor (`RangeError`) rather than ignored — `concurrency: 0` would otherwise resolve with nothing collected.

**A bound that trips throws `CollectorTimeoutError`; it never resolves partially.** Partial attributes weaken a rule's inputs, and partial rules weaken the policy — an empty rule set is an allow under `{ onEmptyRuleSet: "allow" }`. There is no safe "answer with what we got" on an authorization path.

### FailureRecord

`FailureRecord` and `FailureSource` are defined in [`src/failureSource.mts`](src/failureSource.mts). A `FailureSource` is one of three kinds: `collector` (with the pipeline and the collector's name), `deadline` (with the pipeline) or `rule` (with its `ruleType` and `code`).

Where **one decision's** failures came from (#200). Create one per decision and hand the same one to both collects and to `evaluate` (`collect(request, { failures })`, `evaluate(attrs, rules, { failures })`); then ask `sourceOf` with whatever the decision was failed with. The pipelines and `evaluate` still reject with the error **unchanged** — the source is recorded beside it, not wrapped around it, so a transport that tells a deny from a fault by class, and a caller matching its own error, see exactly what was thrown.

What gets recorded: a collector that rejected, threw or overran its own budget (`collector`); a pipeline that overran its deadline (`deadline` — no one collector is answerable); a rule whose `verify` threw, whose `decide` rejected, or that overran a rule budget (`rule`). Every source is recorded by the runner or the evaluator itself and never read off the error, so a collector that throws a `CollectorTimeoutError` it built is recorded under its own position, whatever that error claims. A collector is named by its position, spelled as the server's config path, and by class when the class name is identifier-shaped and at most 64 characters — `attribute.collectors[1] (EntitlementStoreCollector)`, or `rule.collectors[0]` for an object literal — which is also how `CollectorTimeoutError.collector` names the collector that overran.

The record is keyed by the value that was thrown, primitives included, and **the first source recorded for a value wins**: when two collectors of one decision fail with the same shared object, the one whose rejection landed first is named. It is per decision on purpose — nothing is kept process-wide, so a concurrent decision failing on the same shared object cannot rename this one's. Never share one across decisions. `sourceOf` answers `undefined` for a caller's abort reason (a rejection after a collector's or rule's own signal aborted belongs to whatever aborted it) and for anything no pipeline or evaluator recorded.

### Registry\<T\>

Defined in [`src/modules/Registry.mts`](src/modules/Registry.mts). A name-keyed registry with `register`, `get`, `has` and `entries` (a snapshot of the pairs). `register` throws on a duplicate name and `get` throws on a missing one, so a name that was registered can be looked up without a check.

### Module / ModuleContext

`Module`, `ModuleContext`, `PathResolver` and the three factory types (`AttributeCollectorFactory`, `RuleCollectorFactory`, `ResourceParserFactory`) are defined in [`src/modules/types.mts`](src/modules/types.mts). A module has a `name` and an asynchronous `init(context)`; the context carries the `pathResolver`, the module's `config`, and one `Registry` each for attribute-collector, rule-collector and resource-parser factories.

A module registers attribute-collector, rule-collector, and resource-parser factories into the provided registries during `init`. Configuration is passed through `config`. A `RuleCollectorFactory` may return a `Promise`, for a collector whose boot needs I/O (#225); `createApp` awaits it. A host may initialize modules with a wider context: the default server's `ServerModuleContext` (in `@o3co/auth.policy-verifier.server`, defined in [`auth/serverModuleContext.mts`](../server/src/auth/serverModuleContext.mts)) extends this with two registries — `keyResolverRegistry` for JWT key resolvers and `tokenAuthenticatorRegistry` for token authenticators (#219; `createApp` registers the built-in `"jwt"` entry before any module runs, a module may add an alternative under its own name, and `oauth.authenticator` selects one) — and a module that needs either declares `Module<ServerModuleContext>`.

### Types

The remaining contract types, grouped by the file that defines them:

- [`src/types.mts`](src/types.mts) — the decision contract.
  - `Resource` (a parsed resource: its `raw` string, `resourceType` and optional `resourceId`) and `ResourceParser`, which turns a raw string into one and throws `ResourceParseError` for a string outside the syntax it parses.
  - `CollectorContext` — what every collector is handed: the verified `subject`, the `resource`, the `action`, its own `signal`, and optionally the `headers` the transport set, the caller's `requestContext`, and the raw `credential` (only when the composition opted in; never log it). `CollectorRequest` is what a pipeline is handed: the same without the per-collector `signal`, plus an optional caller-side `signal` the pipeline links into its own.
  - `SubjectAttributes` — the verified attributes of the subject, populated by the transport. Core names no field; under the default server's built-in authenticator they are the verified JWT's claims (`sub`, `azp`, `scope`, …) plus `authScheme` (the `Authorization` scheme the token arrived under, not a claim).
  - `Attributes` — the mutable attribute map collectors build and `AttributePipeline` merges; `ReadonlyAttributes` — the read-only view a rule is judged against. The evaluator hands the same live map to every rule, so a rule that wrote into it would change the inputs of every group after it.
  - `AttributeCollector` and `RuleCollector` — the two collector interfaces; a rule collector may return `Rule`s, `AsyncRule`s, or both (`AnyRule`).
  - `Rule` — `ruleType`, `code`, `message` and a `verify` that must be a deterministic, side-effect-free function of the attributes; `AsyncRule` — the same contract answered through an asynchronous `decide` under a deadline (#225), told apart by `isAsyncRule`. See [AGENTS.md — Collector / Rule / Attribute Contract](../../AGENTS.md#collector--rule--attribute-contract).
  - `Decision`, `DecisionReason`, `RuleGroupOutcome` and `RuleOutcome` — the answer and its explanation, as described under [evaluate](#evaluate). A `RuleOutcome` may carry the `evaluation` its rule reported (#244), checked and frozen by `evaluate()`.
  - `ReportRuleEvaluation` and `RuleEvaluation` (with `RuleEvaluationStatus`) — how a rule that fronts a policy evaluator reports the evaluation behind one answer: whether it ran, against which policy revision (`null` being the explicit unknown), and, for a completed one, which policies determined it (#199). `evaluate()` makes one reporter per invocation; a reported revision is held to `POLICY_REVISION_PATTERN` and `POLICY_REVISION_MAX_LENGTH`, and determining policies to `DETERMINING_POLICIES_MAX` and `POLICY_ID_MAX_LENGTH`. See [docs/extending.md](../../docs/extending.md#reporting-the-evaluation-behind-an-answer).
  - `Role` — a role name with its permissions.
- [`src/errors.mts`](src/errors.mts) — the error classes, exported as classes so `instanceof` narrows them: `ResourceParseError` (carries the refused `raw` and a `detail`; a **request** error, which the transport answers 400-class), `CollectorTimeoutError` (carries `pipeline`, `limit`, `timeoutMs` and, for a per-collector timeout, `collector`; **a deny, not a degradation**), `RuleTimeoutError` and `AttributeConflictError`.
- [`src/collectorLimits.mts`](src/collectorLimits.mts) — `CollectorLimits` (see [Collector limits](#collector-limits)), `CollectOptions` (the `{ failures }` second argument of `collect` on both pipelines), and the `DEFAULT_*` bounds.
- [`src/untrusted.mts`](src/untrusted.mts) — `UntrustedRequestContext`, the type of `requestContext`: the caller's own data, sealed so it takes an explicit `readUntrustedRequestContext(...)` to read; `markUntrustedRequestContext(...)` mints one at the transport boundary. See [docs/extending.md — The trust boundary](../../docs/extending.md#the-trust-boundary-requestcontext-is-the-callers).
- [`src/logging/Logger.mts`](src/logging/Logger.mts) — the `Logger` port; [`src/logging/consoleLogger.mts`](src/logging/consoleLogger.mts) is the console-backed implementation.

`KeyResolver` / `KeyResolverFactory` are not core types: they are token-credential plumbing and live in `@o3co/auth.policy-verifier.server` (#170).

### Constants

The `ATTR_*` constants, defined in [`src/keys.mts`](src/keys.mts), are limited to well-known OAuth 2.0 / OIDC and RBAC vocabulary: concepts every consumer of the ABAC engine shares (JWT claims, OAuth scopes, RBAC roles and permissions). Domain-specific attribute keys belong to the consuming service, not to core. Consumers declare their own constants and read/write the same `Attributes` map.

- `ATTR_SCOPES` — OAuth scopes
- `ATTR_PERMISSIONS` — explicit permissions
- `ATTR_ROLES` — roles
- `ATTR_USER_ID` — the subject user ID (JWT `sub`)
- `ATTR_CLIENT_ID` — the client ID (JWT `azp`)

### The attribute key registry

Those five are what the engine decides from, so a collector promoting
caller-supplied data must not write them — see
[docs/extending.md](../../docs/extending.md#the-trust-boundary-requestcontext-is-the-callers).
Core cannot enumerate every such key, though: a package that owns attribute
vocabulary of its own (`@o3co/auth.policy-verifier.cedar` owns `requestAction`,
`requestResourceType`, `requestResourceId`, `requestResourceRaw`) lives outside
core's sight. So the reservation is a registry rather than a frozen set, and a
package reserves its own:

```typescript
import { reserveAttributeKeys } from '@o3co/auth.policy-verifier.core'

export const ATTR_SUBSCRIBER_DID = 'subscriberDid' as const

// At module scope, beside the constants — see reserveAttributeKeys' doc comment
// for why that placement is what makes the ordering hold.
reserveAttributeKeys({
  owner: '@example/subscriber-policy',
  keys: [ATTR_SUBSCRIBER_DID],
  reason: 'resolved from the verified subject by SubscriberDidCollector',
})
```

The registry's exports, all in [`src/keys.mts`](src/keys.mts):

- `RESERVED_ATTRIBUTE_KEYS` — every reserved key, as a **live** read-only set; read it when you need the verdict, never copy it at module scope.
- `reserveAttributeKeys` — reserves a package's keys. Idempotent per owner; two owners claiming one key is refused.
- `attributeKeyReservation` — who owns a key, so a refusal can name the package instead of assuming core.
- `suggestUnreservedAttributeKey` — a rename no package has reserved; what a refusal advises.
- `CORE_ATTRIBUTE_KEY_OWNER` — the owner name core's own five are reserved under.

`RequestContextAttributeCollector` (builtins) is the guard that consults it, and
a collector you write yourself should consult it too.

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
const decision = await evaluate(attrs, rules)
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

- [`src/README.md`](src/README.md) — responsibility, role and invariants of this package's source directory
- [Root README](../../README.md) — full setup, configuration, and server usage
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.md) — built-in collectors, rules, and resource parser
- [`@o3co/auth.policy-verifier.server`](../server/README.md) — Express HTTP server and `createApp`
