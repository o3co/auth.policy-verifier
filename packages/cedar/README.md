# @o3co/auth.policy-verifier.cedar

Co-resident [Cedar](https://www.cedarpolicy.com/) policy evaluation for
[auth.policy-verifier](https://github.com/o3co/auth.policy-verifier), as an
optional plugin package.

The whole Cedar policy set is evaluated by a real Cedar evaluator and enters
the engine's AND-evaluation as **one rule in one group**. TypeScript rule
groups keep working beside it: TS collectors gather the facts, Cedar policies
write judgment over them — **no entity store to build or sync**.

Which evaluator is a deployment decision, made by dependency rather than by
config: this package owns policy loading, the attribute-to-entity mapping and
the rule, and hands the request to whichever `CedarEngine` is registered.
[`@o3co/auth.policy-verifier.cedar-wasm`](../cedar-wasm/README.md) is the
in-process one (official `@cedar-policy/cedar-wasm`, ~15µs per decision, no
network); importing it is all it takes. See [Engines](#engines).

This decouples policy language from PDP topology. Native logic stays
TypeScript — no DSL is ever required — and a deployment that adopts Cedar here
is not binding itself to this verifier: the same `.cedar` files load unchanged
into an embedded evaluator later, or into a cedar-agent when laid out one
policy per file (see [Running out of process](#running-out-of-process)). Design: [#185](https://github.com/o3co/auth.policy-verifier/issues/185).

## Usage

```ts
import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
import { cedarPolicyModule } from "@o3co/auth.policy-verifier.cedar";
import "@o3co/auth.policy-verifier.cedar-wasm"; // registers the in-process engine
import { builtinKeyResolversModule, createApp } from "@o3co/auth.policy-verifier.server";

const app = await createApp({
	pathResolver: import.meta.resolve,
	config,
	modules: [builtinCollectorsModule, builtinKeyResolversModule, cedarPolicyModule],
});
```

```hocon
attribute {
  collectors = [
    { collector = "PayloadSubjectIdCollector" }
    # Promotes action / resourceType / resourceId into attributes — the rule
    # pipeline never sees the request, so the Cedar request is built from these.
    { collector = "RequestFactsCollector" }
  ]
}
rule {
  collectors = [
    { collector = "CedarPolicyRuleCollector"
      # *.cedar files, sorted and concatenated — byte-identical to what a
      # Cedar agent would load. XOR an inline `policies = "..."` string.
      policyDir = "config/policies"

      # What the group answers when no policy determined the request.
      # "deny" is the default; see "No determining policy" below.
      onNoDeterminingPolicy = "deny"

      # Which registered engine evaluates the set. Optional: absent, the
      # preferred registered one — "wasm" whenever cedar-wasm is imported.
      # engine = "wasm"

      principal {
        # type = "User"          # default
        # idAttribute = "userId" # default (ATTR_USER_ID)
        attributes { dept = "department" }   # principal.dept == "eng"
        parents { Group = "groups" }         # principal in Group::"admins"
      }
      resource {
        attributes {
          # entity-reference form: resource.owner == principal
          owner = { attribute = "resourceOwner", entityType = "User" }
        }
      }
      context { mfa = "mfaVerified" }        # context.mfa
    }
  ]
}
```

Request-context fields reach Cedar the same way everything else does — as
attributes. Promote them with the builtins' `RequestContextAttributeCollector`
(the declared-allowlist trust boundary, #123) and map them here; nothing
undeclared can reach a policy.

## Reserved attribute keys

Loading this package reserves the four keys it owns —
`requestAction`, `requestResourceType`, `requestResourceId`,
`requestResourceRaw` — in core's attribute key registry
(`reserveAttributeKeys`, exported by `@o3co/auth.policy-verifier.core`). A
`RequestContextAttributeCollector` mapping whose `to` names one of them is then
refused at boot, naming this package.

That matters most for `requestResourceId`, which `RequestFactsCollector` writes
**only when the parsed resource carried an id**. For an id-less resource such as
`document` nothing else writes it, so a mapping
`{ from = "rid", to = "requestResourceId" }` would have met no competing writer:
`{"resource":"document","action":"read","context":{"rid":"someone-elses-doc"}}`
would have been decided as `document::"someone-elses-doc"`, with the entity
chosen by the caller's own request body. Where the resource *does* carry an id
the two writers collide instead and `AttributeConflictError` denies — fail-closed,
but an unannounced denial rather than a refusal at boot.

The reservation happens at module scope, so it is in place before any collector
of any package is constructed: a composition can only name
`RequestFactsCollector` or `CedarPolicyRuleCollector` in config by importing this
package. If you write a collector that promotes caller-supplied data, consult
`RESERVED_ATTRIBUTE_KEYS` (live, not a snapshot) and reserve your own keys the
same way — see [docs/extending.md](../../docs/extending.md#the-trust-boundary-requestcontext-is-the-callers).

## Semantics

- **Layered PDP.** Cedar's own semantics (forbid overrides permit) hold inside
  the group; the group ANDs with every TypeScript group. During migration both
  are active and compose only toward strictness.
- **No determining policy denies by default.** When no `permit` and no `forbid`
  matched, `onNoDeterminingPolicy` decides what the group answers:

  | value | the group | choose it when |
  | --- | --- | --- |
  | `"deny"` (**default**) | fails | Cedar is authoritative over the surface it is asked about — including the common case where it is the **only** rule group |
  | `"abstain"` | passes | Cedar is one group beside TypeScript rules that own the rest of the surface, and having no opinion outside its own coverage is the intent |

  `"deny"` is Cedar's own implicit deny, and it is the default because the
  default is what a first deployment gets: with Cedar as the only rule group,
  an abstention passes the group and therefore passes the request — the one
  composition where abstaining is indistinguishable from allowing, and also the
  simplest one to assemble. The surrounding engine composes rule groups with
  default-deny; this matches it.

  `"abstain"` is the migration posture and stays a first-class choice: while the
  policy set covers part of the surface and the TypeScript rules hold the rest,
  a request outside Cedar's coverage should be decided by the group that does
  cover it. Selecting it is a statement that another group will decide — so a
  pipeline whose only rule group is Cedar should not.

  Neither value affects an evaluation error, which always denies (below).
- **Evaluation errors always deny, and log.** Cedar reports a policy that
  reads a missing attribute as `deny` with the cause only in diagnostics — and
  an erroring `forbid` stops forbidding, so the top-level decision can read
  `allow` exactly when it is least trustworthy. The rule checks
  `diagnostics.errors` first: any error is a deny regardless of
  `onNoDeterminingPolicy`, and is logged unless `logEvaluationErrors = false`.
- **Entity synthesis is one hop.** Principal and resource entities are
  synthesized per request from the attribute map — attributes, group
  membership, entity references. Multi-hop dereference and hierarchy walks
  need an entity store; needing them is the signal to move to a full Cedar
  deployment, which the same `.cedar` files already fit.

## Engines

This package has no evaluator of its own. `CedarPolicyRuleCollector` loads the
policy set, builds the Cedar request — principal, action, resource, context
and the synthesized entities, inline — from the merged attributes, and hands
both to a `CedarEngine`:

```ts
interface CedarEngine {
  readonly name: string;                 // "wasm", "http", …
  load(source: PolicySource): LoadedCedarPolicySet | Promise<LoadedCedarPolicySet>; // boot: parse-check and compile, or hand over
}
// A loaded set answers either synchronously (in-process) or asynchronously (over I/O):
//   { async: false; isAuthorized(request): CedarDecision }
//   { async: true;  isAuthorized(request, signal): Promise<CedarDecision> }
```

`load` may be asynchronous — a remote engine takes the policy set over the
network — and a set that cannot be loaded still refuses to start: the
collector's factory (`CedarPolicyRuleCollector.create`, what the module
registers) awaits it, and `createApp` awaits the factory.

The kind of policy set the engine returns decides the kind of rule the
collector builds — a `Rule` asked through `verify`, or an `AsyncRule` asked
through `decide` under the server's `verify.ruleTimeoutMs` — and nothing else
changes: config, mapping, the answer table above and the `cedar_deny` the
decision reports are identical across engines. Switching engines is a
dependency change, not a config change (#225).

An engine package registers itself when imported (`registerCedarEngine`, at
module scope), and the collector picks one by its config `engine` key:

| config `engine` | result |
| --- | --- |
| absent | the first registered of `wasm`, `http` — so `wasm` whenever `@o3co/auth.policy-verifier.cedar-wasm` is imported |
| a registered name | that engine; an explicit choice wins over the preference |
| `"wasm"`, package not imported | refuses to start, naming `@o3co/auth.policy-verifier.cedar-wasm` |
| anything else | refuses to start, listing what is registered |

The engines that ship today:

| engine | package | runs | when |
| --- | --- | --- | --- |
| `wasm` | [`@o3co/auth.policy-verifier.cedar-wasm`](../cedar-wasm/README.md) | in-process, synchronous, tens of µs per decision on a small set; ~12 MB of wasm instantiated at import | the policy set is cheaper to evaluate than a loopback hop — most of them; see [Sizing](#sizing-which-engine) |
| `http` | this package (`cedarHttpEngine`, registered by importing it) | out of process: a [cedar-agent](https://github.com/permitio/cedar-agent) over HTTP, asynchronous, one loopback hop per decision | the policy set is large enough that evaluating it in-process competes with request handling, or the evaluator should scale and upgrade apart from the verifier |

Both engines see the same request — principal, action, resource, context and
the synthesized entities, inline — and answer through the same table. What
differs is where the evaluator runs and what the deployment carries: the wasm
package, or a second process.

## Running out of process

`engine = "http"` (or simply not importing the wasm package) sends every
decision to a cedar-agent. The standalone template ships it as a compose
profile that shares the verifier's network namespace, so the agent listens on
loopback and nothing outside the container pair can reach it — the same trust
boundary the verifier's own bind address draws:

```sh
docker compose --profile cedar up --build
```

- **Where the agent is.** `endpoint` in the collector's config entry, else the
  `CEDAR_ENDPOINT` environment variable, else `http://127.0.0.1:8180` — the
  compose service's address, so the profile needs no configuration at all. A
  base URL: the agent's `/v1/policies` and `/v1/is_authorized` are appended.
  Plain `http://` is accepted for loopback hosts only; a routable agent must be
  `https://` (the rule `jwksUri` follows, and for the same reason: the request
  carries the subject's attributes and the answer is an authorization).
  `authentication` in config, else `CEDAR_AUTHENTICATION`, is sent verbatim as
  the `Authorization` header when the agent was started with one.
- **The verifier owns the policies.** At boot the engine `PUT`s the policy set
  to the agent, one entry per `.cedar` file with the file's name as the policy
  id, so the agent holds exactly `config/policies` and nothing is converted or
  mounted twice. Boot retries an unreachable agent for 10 s (a compose sibling
  may be a few hundred milliseconds behind) and then refuses to start; a set
  the agent refuses fails boot at once, with the agent's message.
- **One policy per file.** cedar-agent stores policies one by one, so each
  `.cedar` file — and an inline `policies` string — must hold exactly one
  policy; a file with two is refused at boot. The wasm engine concatenates and
  does not care, so a corpus laid out one policy per file runs under both, and
  reads better under this one: `diagnostics.reason` then names files
  (`10-permit-eng`) rather than `policy0`.
- **One collector per agent.** `PUT /v1/policies` replaces the agent's whole
  set, so a second `CedarPolicyRuleCollector` pointed at the same endpoint is
  refused at boot rather than silently overwriting the first.
- **Failure after boot is a deny.** An agent that is unreachable, answers
  non-2xx, or answers something that is not a decision makes the rule fail
  and log (`cedar authorization call failed`); it never abstains, whatever
  `onNoDeterminingPolicy` says. Each call runs under the server's
  `verify.ruleTimeoutMs` (default 2000 ms), answering `rule_timeout` when the
  agent is slower than that.
- **Two Cedar versions.** cedar-agent 0.2.2 evaluates with cedar-policy 2.4;
  the wasm package with Cedar 4.12. Policies written to the older grammar run
  under both; a policy using a newer construct will be refused by the agent at
  boot, which is the right place to find out.

## Sizing: which engine

Measured, not guessed: one request of the shape the collector sends (two
entities inline, one context field), against policy sets in which every
policy has to be considered, 2000 decisions each. Apple M3, Node 26,
`@cedar-policy/cedar-wasm` 4.12.0 in-process; `permitio/cedar-agent:0.2.2`
in Docker Desktop on the same machine, reached through a published loopback
port. Microseconds per decision:

| policies | wasm p50 | wasm p99 | agent p50 | agent p99 |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 34 | 90 | 346 | 1281 |
| 10 | 45 | 78 | 328 | 1897 |
| 100 | 134 | 238 | 395 | 791 |
| 1000 | 1111 | 1409 | 969 | 1595 |

How to read it:

- The wasm figure is time the verifier's event loop is **blocked**; the agent
  figure is mostly waiting, and costs the loop only the `fetch` overhead (on
  the order of 100 µs of it).
- On this setup the hop costs roughly 300 µs, so in-process wins outright up
  to a few hundred policies, and the two cross near a thousand policies of
  this shape — where the agent's native evaluator is already faster than the
  wasm one and the verifier stops paying for evaluation on its own loop.
- Docker Desktop on macOS routes the published port through a virtual
  machine; a Linux host with the compose profile's shared network namespace
  pays less for the hop, which moves the crossover down. Policies with heavier
  conditions or larger entity sets move it down too. Measure your own corpus
  before deciding: the script is three `fetch` calls and one
  `statefulIsAuthorized` loop.
- Below the crossover, choose the agent anyway when the evaluator should
  scale or upgrade apart from the verifier, or when the 12 MB wasm should not
  be in the image. Above it, choose wasm anyway when a second process is not
  worth operating. The switch is a dependency change — config, mapping and
  policies stay put.

## Version pinning

The Cedar evaluator's version is the engine package's concern:
`@o3co/auth.policy-verifier.cedar-wasm` pins `@cedar-policy/cedar-wasm`
exactly, because Cedar minor releases can carry policy-language changes and
upgrades should be deliberate. This package depends on no evaluator.
