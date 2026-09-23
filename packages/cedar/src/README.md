# cedar/src

Last updated: 2026-09-23

The source of [`@o3co/auth.policy-verifier.cedar`](../README.md). The package
README says what the package does and how to configure it; this page says
which file does what, so a change lands in the right one.

## Responsibility

This directory turns a Cedar policy set into one rule of the verifier's
AND-evaluation. It owns the `CedarEngine` port and its registry, the steps
that feed an engine (loading policies, mapping attributes to a Cedar request)
and interpret its answer (the rule), one engine of its own (`http`), and the
assembly that makes all of it reachable from `createApp`. It owns no
in-process evaluator; that is [`cedar-wasm`](../../cedar-wasm/README.md). Its
only package dependency is core; the files below split into four groups by
what changes them.

## The port: `engine.mts`

- **Role.** The line between this package and whatever evaluates a policy
  set: `CedarEngine`, the loaded set (sync or async), `CedarDecision`,
  `CedarEngineLoadContext`, `CedarEngineError`, and the process-wide engine
  registry (`registerCedarEngine`, `resolveCedarEngine`).
- **Owns.** The contract every engine meets, including the revision
  confirmation contract (#244), and how an engine is chosen when config names
  one and when it does not.
- **Does not own.** Any engine. It imports nothing that evaluates or does
  I/O, and only types from `mapping.mts` and `policySource.mts`.
- **Why separate.** It is the replacement point: `cedar-wasm` and any other
  engine package build against this file (plus the `CedarRequest` and
  `PolicySource` types it names), not against the collector, and the registry lives in a
  `Symbol.for` slot so two copies of this package on one dependency graph
  still share one registry.

## The process: from attributes to a rule outcome

| file | role |
| --- | --- |
| [`CedarPolicyRuleCollector.mts`](CedarPolicyRuleCollector.mts) | The rule collector. At boot: validates its config entry, loads the policy source, resolves and loads the engine, refuses unsafe combinations (`"abstain"` or `requireConfirmedRevision` over an engine that cannot support them). Per request: builds the Cedar request and turns the engine's answer into pass, fail or a logged deny, with the evaluation report. |
| [`RequestFactsCollector.mts`](RequestFactsCollector.mts) | Attribute collector that copies the parsed action and resource into attributes, because a rule never sees the request itself. |
| [`mapping.mts`](mapping.mts) | Resolves the principal / resource / context mapping from config once, and builds a `CedarRequest` (entities inline) from merged attributes per request. `CedarInputError` when the attributes cannot be shaped into one. |
| [`cedarJson.mts`](cedarJson.mts) | Cedar's JSON vocabulary (entity uid, value, entity, context), declared here so the mapping follows Cedar's documented formats rather than one evaluator's bindings. Types only. |
| [`keys.mts`](keys.mts) | The four `request*` attribute keys and their reservation in core's registry, done at module scope. |
| [`policySource.mts`](policySource.mts) | Reads `*.cedar` files (or the inline string) and computes the policy revision. The only file here that touches the filesystem, and only at boot. |

- **Owns.** Everything the package README describes under Semantics and
  Policy revision: what an answer means, not how it was computed.
- **Does not own.** Evaluation and transport. The collector talks only to the
  port and never imports an engine.
- **Why separate from the port.** These change with the verifier's semantics
  (mapping options, answer table, revision rules); the port changes only when
  what an engine must provide changes. Keeping them apart means engine code
  never has to know about the collector.

## The external connection: `httpEngine.mts`

- **Role.** The `http` engine: a cedar-agent client behind the port. It pushes
  the policy set at boot (`PUT /v1/policies`) and asks per request
  (`POST /v1/is_authorized`), reading `endpoint` / `authentication` from the
  collector's config entry or from `CEDAR_ENDPOINT` / `CEDAR_AUTHENTICATION`.
- **Owns.** The agent wire format, the endpoint and token rules (loopback-only
  `http://`), boot retries, one collector per agent, and rejecting malformed
  answers.
- **Does not own.** What an answer means. It returns a `CedarDecision` or
  rejects with `CedarEngineError`; the collector decides the rest.
- **Why a separate file.** It is the only file here that does network I/O,
  and it depends on the port, not the other way round. The collector reaches
  it only through the registry.

**Why the http engine ships in this package while wasm is its own package.**
The recorded reasons are about the wasm side:
[`@cedar-policy/cedar-wasm`](../../cedar-wasm/package.json) is a pinned
dependency of about 12 MB, instantiated when imported, so a deployment that
does not want it in the image leaves the package out (see the
[cedar-wasm README](../../cedar-wasm/README.md)). The http engine has no such
cost: it adds no dependency and uses the platform's global `fetch`. The one
statement in the code, the comment on the registration in `index.mts`, is that
it "needs no evaluator", so importing this package registers it as the
fallback when no in-process engine was imported. No further rationale for
keeping it here instead of in a package of its own is recorded.

## Assembly and public surface

| file | role |
| --- | --- |
| [`module.mts`](module.mts) | `cedarPolicyModule`: registers `RequestFactsCollector` and `CedarPolicyRuleCollector` (through its async `create`) under the names config uses. Nothing else. |
| [`index.mts`](index.mts) | The package's public surface: every export lives here, and importing it registers the `http` engine. |

- **Why separate.** `module.mts` is the only file that knows the collector
  names config uses and the registries they go into. `index.mts` is the only
  file that registers an engine; the other import-time effect in this
  directory is the key reservation in `keys.mts`.

## Tests

[`__tests__/`](__tests__/) holds a test file for each source file except
`mapping.mts`, `cedarJson.mts` and `index.mts`; the mapping is tested through
`CedarPolicyRuleCollector.test.mts`. `scriptedEngine.mts` there is a stand-in engine that evaluates nothing, used
to test the port and the collector without a real evaluator; the real
evaluator is tested end to end in `packages/cedar-wasm`.
