# @o3co/auth.policy-verifier.cedar-wasm

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
