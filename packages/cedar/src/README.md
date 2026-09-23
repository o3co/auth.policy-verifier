# cedar/src

Last updated: 2026-09-24

The source of [`@o3co/auth.policy-verifier.cedar`](../README.md). The package README says
what the package does and how to configure it; this page says how the source is divided and
what holds across it.

## Responsibility

- **Role.** Turns a Cedar policy set into one rule of the verifier's AND-evaluation, reachable
  from `createApp` through `cedarPolicyModule`.
- **Owns.** The `CedarEngine` port and its process-wide registry; the steps that feed an
  engine (loading the policy set, mapping attributes to a Cedar request) and interpret its
  answer (the rule, with everything the package README describes under Semantics and Policy
  revision); the `request*` attribute keys and the collector that writes them; one engine of
  its own, `http`, a cedar-agent client.
- **Does not own.** Evaluation: the in-process evaluator is
  [`cedar-wasm`](../../cedar-wasm/README.md), which builds against the port, and the `http`
  engine only carries the request to a cedar-agent and its answer back.
- **Why a separate module.** Nothing of Cedar loads unless a deployment imports this package;
  neither core nor the server depends on it. The `http` engine is here, and registered on
  import, because it needs no evaluator (the comment on the registration in `index.mts`); it
  adds no dependency and uses the platform's `fetch`. The wasm engine is a package of its own
  because its evaluator is a pinned dependency of about 12 MB, instantiated when imported. No
  further rationale for the split is recorded.

## Structure

The source falls into four parts, separated by what changes them:

- **The port** — [`engine.mts`](engine.mts): the contract every engine meets, including the
  revision confirmation contract, and how an engine is chosen. It changes only when what an
  engine must provide changes; `cedar-wasm` and any other engine build against it, not
  against the collector.
- **The process** — the rule collector, the request-facts collector, the mapping, the Cedar
  JSON vocabulary, the keys and the policy source. These change with the verifier's
  semantics: mapping options, the answer table, revision rules.
- **The external engine** — talking to a Cedar evaluator in another process. It changes with
  that process's wire protocol, and nothing else in the package does I/O over the network.
- **Assembly** — registering the collectors under the names configuration uses, and the
  package's public surface. It changes when a collector or an export is added.

## Dependencies

- The only package dependency is `@o3co/auth.policy-verifier.core`.
- The port imports nothing that evaluates or does I/O, and from this directory only types
  (the request and the policy source).
- The collector talks only to the port and never imports an engine; it reaches the `http`
  engine through the registry. The engine depends on the port, not the other way round.
- Only `index.mts` imports the `http` engine.

## Invariants

- The engine registry lives in a `Symbol.for` slot, so two copies of this package on one
  dependency graph share one registry —
  [`__tests__/engine.test.mts`](__tests__/engine.test.mts).
- `index.mts` is the only file that registers an engine, and `keys.mts` the only one that
  reserves attribute keys; both do it at import.
- The only I/O here is reading the policy set, at boot (`policySource.mts`), and the `http`
  engine's calls to its agent.
- An evaluation error, a failed call, a request that could not be built or an answer from a
  revision other than the one loaded is a logged deny, never an abstention — the answer
  table in `CedarPolicyRuleCollector.mts`,
  [`__tests__/CedarPolicyRuleCollector.test.mts`](__tests__/CedarPolicyRuleCollector.test.mts).
- Nothing here evaluates Cedar, so the port and the collector are tested against a stand-in
  engine that evaluates nothing ([`__tests__/scriptedEngine.mts`](__tests__/scriptedEngine.mts));
  the real evaluator is tested end to end in `packages/cedar-wasm`.
