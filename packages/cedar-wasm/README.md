# @o3co/auth.policy-verifier.cedar-wasm

Last updated: 2026-09-26

The in-process Cedar engine for
[`@o3co/auth.policy-verifier.cedar`](../cedar/README.md): the official
[`@cedar-policy/cedar-wasm`](https://www.npmjs.com/package/@cedar-policy/cedar-wasm)
bindings behind cedar's `CedarEngine` port.

Importing this package is all a deployment does to select it:

```ts
import { cedarPolicyModule } from "@o3co/auth.policy-verifier.cedar";
import "@o3co/auth.policy-verifier.cedar-wasm";
```

The import registers the engine as `"wasm"`. `CedarPolicyRuleCollector` picks
it whenever its config names no `engine`, and `engine = "wasm"` spells the
same choice out — that setting refuses to start when this package was not
imported, naming it. Nothing else about the collector's config changes with the
engine; see cedar's README for the whole of it.

It also vouches for the policy revision behind every answer
(`confirmsRevision`, #244): the set is compiled in this process, from the files
the revision was computed over, under an id nothing else holds — so an answer
cannot have come from any other policies. It is the engine
`requireConfirmedRevision = true` boots over; see cedar's [Policy
revision](../cedar/README.md#policy-revision-which-policies-decided).

## Responsibility

**Role.** One engine behind cedar's `CedarEngine` port
([`engine.mts`](../cedar/src/engine.mts)). It depends on
`@o3co/auth.policy-verifier.cedar` and on `@cedar-policy/cedar-wasm`. No
package in this repository depends on it (only the integration tests do); a
deployment imports it.

**Owns** ([`src/wasmEngine.mts`](src/wasmEngine.mts)):

- Parsing each policy file at boot, so a syntax error names its file;
  naming each policy for its file (cedar's `namePolicies`, #199), so Cedar's
  `diagnostics.reason` — and a decision's `determiningPolicies` — say
  `30-forbid-contractors` or `20-rules#2` rather than a positional `policy7`;
  refusing a set where two policies would share an id, a policy in a file
  named only `.cedar`, or a template, which nothing here would link; and
  compiling the set once into wasm memory under an id minted per load.
- Evaluating each request against that compiled set, synchronously, and
  rendering the bindings' answer as a `CedarDecision`.
- Naming the revision of the source it compiled on every answer.
- The exact version of `@cedar-policy/cedar-wasm`.
- Registering itself as `"wasm"` when imported
  ([`src/index.mts`](src/index.mts)).

**Does not own.** Policy loading, the policy revision itself, the
attribute-to-request mapping, what an answer means (the answer table,
`onNoDeterminingPolicy`, the revision check) and which engine is selected. All
of that is cedar's, and is identical whichever engine runs.

**Why a separate package.** The cost below: about 12 MB of wasm instantiated
on import. Kept out of cedar, it is carried only by a deployment that
evaluates in-process; one that runs cedar's `http` engine never loads it.

## What it costs, and when to choose it

The policy set is compiled once, at boot, into wasm memory; each request
references the compiled set and re-parses nothing. A decision is synchronous,
deterministic, and takes a few tens of microseconds — no network, no timeout
to tune, no second process to run. That is the right trade for a policy set
whose evaluation is cheaper than a loopback hop, which is most of them.

The cost is paid at import: the wasm module is about 12 MB on disk and is
instantiated when the bindings load, on the verifier's own event loop. A
deployment whose policy set is large enough that evaluation competes with
request handling — or that wants Cedar's evaluator scaled and upgraded apart
from the verifier — runs cedar's `http` engine against a cedar-agent instead and leaves this
package out — see [Running out of process](../cedar/README.md#running-out-of-process)
and the measured [sizing table](../cedar/README.md#sizing-which-engine). That is
a dependency change, not a config change.

## Version pinning

`@cedar-policy/cedar-wasm` is pinned exactly: Cedar minor releases can carry
policy-language changes, so upgrades should be deliberate and re-validated,
not fall out of a range resolution.

The re-validation is a suite (#198):
[`cedar-cli-equivalence.test.mts`](../../tests/integration/src/cedar-cli-equivalence.test.mts)
holds this engine, behind `CedarPolicyRuleCollector`, to the official `cedar`
CLI at the pinned version.
- **What it compares.** For every request of a fixture corpus, the CLI is
  asked exactly the request the collector built, and both evaluators must agree
  on the decision, on the policies that determined it, and on which policies
  raised errors. The request itself must be the one the case records, so a
  change to how requests are built shows as a diff. The corpus covers the cases
  the entity synthesis decides:
  - group membership, direct and transitive;
  - entity references;
  - a missing attribute;
  - `forbid` over `permit`;
  - the context allowlist;
  - `resource.idWhenAbsent`.
- **Policy names.** Each fixture policy carries `@id` with the id its file
  gives it. The CLI names a policy by `@id`, and otherwise by its position, so
  this is how it answers in this engine's names.
- **How the versions stay together.** CI installs `cedar-policy-cli` at the
  version read from this package's `package.json`, so bumping the pin moves the
  CLI with it. A CLI at any other version fails the suite's version check.
- **Running it locally.** Install the CLI at the pinned version, then build
  and run the suite. Without a CLI this engine's half is skipped, with a
  notice. The suite's other half measures the `http` engine against a real
  cedar-agent (#284, see the cedar package's README).

  ```sh
  cargo install cedar-policy-cli --locked --version \
    "$(node -p 'require("./packages/cedar-wasm/package.json").dependencies["@cedar-policy/cedar-wasm"]')"
  pnpm run build
  CEDAR_CLI="$(command -v cedar)" pnpm --filter @o3co/auth.policy-verifier.integration-tests \
    exec vitest run cedar-cli-
  ```
