# @o3co/auth.policy-verifier.cedar

Last updated: 2026-09-26

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

## Responsibility

**Role.** An optional plugin. A composition passes `cedarPolicyModule` to the
server's `createApp`, which registers `RequestFactsCollector` and
`CedarPolicyRuleCollector` for config to name. It depends on
`@o3co/auth.policy-verifier.core` only; neither core nor the server depends on
it, and engine packages such as
[`cedar-wasm`](../cedar-wasm/README.md) depend on it.

**Owns.**

- Policy loading, the policy revision and the policy ids (`loadPolicySource`,
  `computePolicyRevision`, `namePolicies`).
- The mapping from merged attributes to a Cedar request, with entities
  synthesized inline.
- The rule: how an engine's answer becomes pass, fail or a logged deny
  (`onNoDeterminingPolicy`, evaluation errors, the revision check).
- The `CedarEngine` port and the process-wide engine registry and selection.
- The four attribute keys it reserves (see
  [Reserved attribute keys](#reserved-attribute-keys)).
- The out-of-process `http` engine (a cedar-agent client).

**Does not own.**

- An in-process evaluator. It has no Cedar dependency;
  [`cedar-wasm`](../cedar-wasm/README.md) supplies one and pins its version.
- An entity store. Entities are built per request, one hop deep.
- How rule groups combine. That is core's AND-evaluation; the Cedar policy set
  is one group in it.
- Parsing the request. The server does that, through the configured resource
  parser, before any collector runs; `RequestFactsCollector` only copies the
  result into attributes.

**Why a separate package.** Cedar is opt-in: nothing of it loads unless a
deployment imports this package. Its vocabulary (the `request*` attribute
keys, entity mapping) stays out of core, whose `ATTR_*` constants are
reserved for OAuth/OIDC/RBAC concepts. The evaluator lives one package further
out so that which evaluator runs is a dependency choice, not a config change.

Responsibility, role and invariants of the source directory: [src/README.md](src/README.md).

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
      # *.cedar files, read in name order — each byte-identical to what a
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

      # When the principal and the resource are one entity — a user acting
      # on their own record — how the two mappings are reconciled. "strict"
      # is the default; see "One entity per uid" below.
      # sharedEntity = "strict"
    }
  ]
}
```

Request-context fields reach Cedar the same way everything else does — as
attributes. Promote them with the builtins' `RequestContextAttributeCollector`
(the declared-allowlist trust boundary, #123) and map them here; nothing
undeclared can reach a policy.

**Map parents only from attributes the caller cannot choose.** `parents` are
memberships Cedar trusts: `principal in Group::"admins"` is true because the
mapping says so. A caller-supplied request-context field mapped to
`principal.parents` hands the caller their own group memberships. Feed them
from verified sources — token claims, a directory lookup — not from the request.

**A resource fact is a principal fact wherever the principal reaches the
resource.** The caller chooses the resource, and a policy can reach it from the
principal in two ways:
- **Through `in`.** Membership is transitive through the entities a request
  carries. Say the principal is in `Group::"team"` and the request's resource is
  that team: the team's mapped parents then extend the principal's ancestry.
- **Through an entity reference.** Say a principal attribute references the
  resource's entity: `principal.team.budget` then reads the resource
  mapping's `budget`.

So any fact the resource mapping gives — parents and attributes alike — is as
trusted as its source. Map it from the request context only where the caller
may decide it.

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

  `"abstain"` is refused at boot with an out-of-process engine (`engine =
  "http"`): an agent that restarted comes back with no policies and answers
  every request "no determining policy" — exactly what a covered request that
  matched nothing answers — so under `"abstain"` every `forbid` would silently
  stop applying.

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
- **One entity per uid (#282).** A role names an entity; it is not one. A user
  acting on their own record is the principal and the resource at once. Cedar
  holds one description per entity, refuses two different entries for one uid,
  and lets `principal` and `resource` both read whatever that description says.
  So the request carries the entity once, and `sharedEntity` decides how the two
  mappings' descriptions are reconciled:
  - **`"strict"` (default).** The principal's mapping describes the entity. The
    resource's may repeat what it says but add nothing: no attribute or parent
    the principal's mapping does not give. So nothing the resource mapping says
    of that entity can reach `principal`.
    - **What both declare must agree, an omission included**, since an omitted
      attribute is what makes a policy reading it deny. So a config that maps
      `dept` on both sides (for `principal.dept == resource.dept`), or `Group`
      parents on both sides, passes self-access only when the resource side
      supplies the same values.
    - **What passes as one entity** is a request whose resource-mapping names
      and parent types are absent on it, such as a document's `owner` on a
      user's own record.
  - **`"merge"`.** The deployment states that its resource mapping's sources
    are as trusted as its principal mapping's. What both declare must agree,
    and what only one declares is added. On self-access, a policy then sees
    through `principal` what only the resource mapping gives: `principal.x`
    reads an `x` only it declares, and `principal in Group::"g"` holds for a
    membership only it declares. Choose it only where no caller-supplied
    attribute feeds the resource mapping.

  The action is a role too, one no mapping describes. A caller who names the
  request's own action as the resource may add nothing to it, under either
  setting: there is no mapping of the action to trust the resource's as. A
  config whose `principal.type` is its `action.type` is refused at boot.

  What cannot be reconciled is refused like any request the attributes cannot
  supply (`not_invoked`, logged, naming the attribute or parent type), never
  settled by picking a side.
  - The log says whether the resource would *add* a fact, which `"merge"` would
    admit, or whether the two mappings *disagree*, which nothing would.
  - A request whose entities would be their own ancestors is refused too. Cedar
    would refuse it whole.

## Policy revision: which policies decided

Every answer of the rule reports the evaluation behind it (#244). The report
goes to the reporter core hands `verify` / `decide` for that one call, and core
carries it onto the decision: into the `decision` log event always, and into the
response under `verify.evaluationInResponse = "include"`. The rule itself still
answers a boolean, so an evaluator that predates the reporter reads a deny as a
deny.

A denial is `cedar_deny` whether or not a policy produced it; this is what
tells them apart:

| the rule answered because | `evaluation.status` | the revision |
| --- | --- | --- |
| Cedar answered without errors — a permit, a forbid, or no policy determining the request | `completed` | `revision`, when the engine vouches for it |
| Cedar answered with evaluation errors | `failed` | `revision`, when the engine vouches for it |
| the call itself failed | `failed` | `revision: null` — nothing answered, so nothing vouched |
| the engine named a revision other than the one loaded, or policies it never loaded (#283) | `failed` | `revision: null` — it answered from a policy set this verifier did not load |
| the engine named no revision, under `requireConfirmedRevision` | `failed` | `revision: null` |
| the request could not be built from the attributes, so Cedar was not asked | `not_invoked` | no revision key at all |

**What the revision is.** `sha256:` and the lowercase hex SHA-256 of

```text
auth.policy-verifier.cedar/policy-set/v1\n
<bytes>:<name>,<bytes>:<text>,          ← once per *.cedar file, in load order
```

where `<bytes>` is the decimal UTF-8 byte length of what follows it, `<name>`
is the file's bare name (`policies` for the inline set) and `<text>` its
contents. `loadPolicySource({ policyDir }).revision` gives it for a directory
— the same filter, sort and decoding the collector uses — and
`computePolicyRevision(files)` for a list already in hand, so CI can compute
the revision of what it is about to ship and compare it with what production
reports. It is computed once, at boot, from the very files handed to the
engine.

- **Same contents, same revision** — on any replica, at any mount path. The
  directory is deliberately not part of it, and no path ever appears in a
  decision.
- **A changed policy changes it even when its policy id does not.** Policy ids
  are made from file names under either engine (below), and do not move when a
  policy's text is edited — a numbered one moves when policies around it are
  added, removed or reordered (below). The revision does.
- **A rename changes it**, because the file name is what its policies are
  called — the id cedar-agent is given under the http engine, and the id a
  decision's `determiningPolicies` names under either.
- **The framing is there because concatenation is not injective**: `"X\n"` + `"Y"`
  and `"X"` + `"\nY"` are one policy text and two policy sets.

**It is the text as loaded that is hashed**, so what changes the text changes
the revision, policy for policy identical or not. Three things do that across
machines: line endings (a checkout with `core.autocrlf` turns `\n` into
`\r\n`), a byte-order mark (kept as U+FEFF by the UTF-8 decoder), and the
Unicode normalization of a non-ASCII file *name* (NFC on one filesystem, NFD on
another). Pin line endings for `*.cedar` in `.gitattributes`, and keep file
names ASCII, if replicas built on different machines must agree.

**What it does not cover.** The collector's mapping, `onNoDeterminingPolicy`,
the engine and its version, and the attributes the request was decided over
all shape an answer too. The revision says which policies were evaluated. It is
not a promise that evaluating them again gives the same answer; to explain a
decision later, keep the deployed version and its config beside it.

**`revision` versus `loadedRevision`.** `revision` is a claim about what was
*evaluated*, so it is set only when the engine vouches for that answer. The
wasm engine does: the set is compiled in-process from the files that were
hashed, under an id nothing else holds. The http engine cannot: cedar-agent
answers `{ decision, diagnostics }` and does not say which policies it holds,
and a restarted agent comes back empty. There the rule reports `revision: null`
and the digest of what it pushed at boot as `loadedRevision` — worth recording,
and not proof of what ran. An engine that names a revision *other* than the
loaded one is answering from a policy set this verifier did not load, and the
rule fails it closed — and logs it whatever `logEvaluationErrors` says, because
that is a fault of the deployment and not a policy reading a missing attribute.

**What the http engine can tell (#283).** It cannot vouch for an answer, but it
can tell a foreign one. The policy ids an answer names are the one thing
cedar-agent gives back about its set: the policies that determined it, and the
policy each evaluation error names. The engine pushes each policy under an id
carrying its load's mark (below), so an answer naming any other id, in either
list, came from a set this verifier did not load. The errors count as much as
the determining policies: a foreign set can answer with errors alone. Three
ways that happens:
- the set was replaced under the agent;
- an agent restarted on its own `--policies`;
- a replica with other files, during a rolling deploy, shares the agent.

Such an answer is failed and logged like a foreign revision, never read. The
log line carries the reason, `foreign: "unknown policy"` or `"unreadable
policy"`. When the id is one of this load's own policies under another mark,
the line also carries that mark. That is the same corpus loaded from other
files, such as a rolling deploy sharing the agent, and the mark tells an operator
which revision took it. It is what the other side spelled, unverified. An id
that merely ends in `@` and 16 hex, as a file may be named, gives no mark.

**The mark is neither a secret nor an authenticator.** Anyone can learn the
ids:
- they are in every answer;
- they are in the agent's `GET /v1/policies`;
- they can be computed from the policy files.

So the mark catches a set this verifier did not load by mistake. It does
nothing against someone holding the agent's token. A token holder can rewrite a
policy under its own marked id, or delete one, and the answers still read as
this load's. No check of an answer can see that. The agent's token is the
boundary (see [Running out of process](#running-out-of-process)), and that is
why the engine still does not declare `confirmsRevision`. Reading the agent's
set back and comparing it with what was pushed would catch it between answers,
though not within one; that is not done today.

**`requireConfirmedRevision = true`** is for a deployment whose audit has to
name the policies behind every decision: an answer nobody vouched for becomes a
deny — always logged, like the mismatch above — instead of a permit of unknown
origin. It is refused at boot over
an engine that does not declare `confirmsRevision` — today, `engine = "http"` —
because there every answer would be that deny.

**Which policies determined it (#199).** A `completed` evaluation also names
the policies Cedar says determined the answer — its `diagnostics.reason`: for
an allow the permits that applied, for a deny the forbids that did, and `[]`
when none applied (the implicit deny, or an abstention under
`onNoDeterminingPolicy = "abstain"`):

```json
{ "status": "completed", "revision": "sha256:…", "determiningPolicies": ["30-forbid-contractors"] }
```

- **The ids are the file names**, the same under both engines
  (`namePolicies`): a file that holds one policy is named for the file without
  `.cedar` (`30-forbid-contractors`), and the policies of a file that holds
  several — which only the wasm engine accepts — are numbered in the file's
  order (`20-rules#1`, `20-rules#2`). The inline set's are `policies`, or
  `policies#1`…. A layout that would give two policies one id (`a.cedar`
  holding two, beside `a#1.cedar`) is refused at boot, naming both files, and
  so is a policy in a file named only `.cedar`, which has no name to give.
- **A number is a position, not a name.** Adding, removing or reordering a
  policy in a file that holds several renumbers the ones after it, and a file
  that gains a second policy turns `a` into `a#1` — so `20-rules#2` in one
  revision can be another policy in the next. An id means something beside its
  revision. Where ids must stay put — a dashboard, an alert keyed on one — lay
  the corpus out one policy per file, which the http engine requires anyway.
- **Sorted, each once, at most 32.** Cedar keeps `reason` in a set, so it is
  sorted to give equal attributes an equal record. What does not fit, and an
  id core cannot carry — a file name over 128 UTF-16 units, or with a control
  character in it — is counted in `determiningPoliciesOmitted` instead. The
  bounds are those of the core that checks the report — the server's — applied
  through its reporter (`report.boundDeterminingPolicies`).
- **Only a completed answer names any.** A `failed` one names none: Cedar's
  errors mean the answer is the rule failing closed, not the policies deciding.
- **Only to an evaluator that reads them.** A core older than #199 refuses the
  keys, and its reporter has no `boundDeterminingPolicies`; under a server that
  predates them the rule reports the rest of the evaluation without them.
  Upgrading this package ahead of the server is safe; the ids appear once the
  server catches up.
- **Beside `revision: null`** — every answer of the http engine — the ids are
  what cedar-agent answered, as unconfirmed as the revision. Each must be one
  this load pushed, so an item the agent answers in a form that is not an id
  makes the answer foreign (#283), not a count.

## Engines

This package has no evaluator of its own. `CedarPolicyRuleCollector` loads the
policy set, builds the Cedar request — principal, action, resource, context
and the synthesized entities, inline — from the merged attributes, and hands
both to a `CedarEngine`. The port and its types are defined, with their
documentation, in [`src/engine.mts`](src/engine.mts); the contract in short:

- An engine has a `name` (the registry key and the config value that selects
  it), declares up front whether its policy sets answer asynchronously
  (`async`), and may declare that every answer names the revision it evaluated
  (`confirmsRevision`, #244). Both declarations come before `load`, so the
  collector can refuse an unsafe configuration before loading has side
  effects.
- `load` is called at boot with the `PolicySource` and a load context carrying
  the collector's whole config entry (an engine reads and validates its own
  keys there, such as the http engine's `endpoint`) and a logger. It returns
  the loaded set, possibly as a promise, or throws `CedarEngineError` to
  refuse the set.
- A loaded set answers either synchronously (in-process), or asynchronously
  with an `AbortSignal` for the rule's deadline (over I/O). Its `async` must
  match the engine's declaration.
- An answer is a `CedarDecision`: the decision; the ids of the determining
  policies, which a decision records (#199), so an engine names its policies
  with `namePolicies` and reads its evaluator's items as ids;
  the evaluation errors as text; optionally the revision it was evaluated
  against; and `foreign` when the engine can tell the answer did not come from
  the set it loaded, though it cannot vouch for one that did (#283). An
  `allow` names at least one determining policy: Cedar allows only on a
  permit, and one naming none is refused as not a decision. Both lists
  must be lists — the rule fails an answer otherwise. A call that failed
  outright rejects with `CedarEngineError`.

`CedarDecision.revision` is the port's confirmation contract (see [Policy
revision](#policy-revision-which-policies-decided)): an engine names
`source.revision` on an answer only if that answer provably came from the set
compiled from that source. It is per answer, not per `load`, because that is
the only moment the claim is true of a remote engine.

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
module scope), and the collector picks one by its config `engine` key
(`resolveCedarEngine` in [`src/engine.mts`](src/engine.mts)):

| config `engine` | result |
| --- | --- |
| absent | the first registered of `wasm`, `http` — so `wasm` whenever `@o3co/auth.policy-verifier.cedar-wasm` is imported |
| a registered name | that engine; an explicit choice wins over the preference |
| `"wasm"`, package not imported | refuses to start, naming `@o3co/auth.policy-verifier.cedar-wasm` |
| anything else | refuses to start, listing what is registered |

**Name the engine.** Left absent, which process decides authorization is
settled by what the dependency graph happens to import — a transitive
dependency that pulls in the wasm package flips a deployment from
out-of-process to in-process — and nothing in the config shows it. The
collector therefore logs a warning at boot when `engine` is absent (`cedar
engine selected by default — set engine …`), and states the engine at `info`
when it is named. The registry is process-wide, not per copy of this package,
so two copies on the graph still see one set of engines.

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
echo "CEDAR_AUTHENTICATION=$(openssl rand -hex 32)" >> .env   # the agent's token, required
docker compose --profile cedar up --build
```

- **Where the agent is.** `endpoint` in the collector's config entry, else the
  `CEDAR_ENDPOINT` environment variable. Neither refuses to start with `no cedar
  engine endpoint is configured`, naming both ways out — this engine is also
  what a deployment gets when it has not imported the wasm package, and that
  is the mistake worth naming. The template's compose file sets
  `CEDAR_ENDPOINT=http://127.0.0.1:8180`, the profile's address. A base URL:
  the agent's `/v1/policies` and `/v1/is_authorized` are appended.
  Redirects are not followed, so this must be the URL that answers those calls
  itself: behind an ingress that answers with a 3xx, every decision is a deny
  and a 3xx to the policy load fails boot.
  Plain `http://` is accepted for loopback hosts only; a routable agent must be
  `https://` (the rule `jwksUri` follows, and for the same reason: the request
  carries the subject's attributes and the answer is an authorization).
  `authentication` in config, else `CEDAR_AUTHENTICATION`, is sent verbatim as
  the `Authorization` header when the agent was started with one. A token that
  cannot be sent as a header — an ASCII control character other than a tab
  inside it, a character above U+00FF — fails boot, naming where it came from
  but not its value.
- **Authenticate the agent.** An agent without `--authentication` is a *write*
  oracle over the policy set: anything that reaches its port can
  `PUT /v1/policies` a `permit(principal, action, resource);` and every later
  decision allows. Loopback in a shared network namespace narrows who can
  reach it; it does not make the token optional, and outside a private
  namespace it MUST be set. The template's compose profile starts the agent
  with `CEDAR_AGENT_AUTHENTICATION` from the same `CEDAR_AUTHENTICATION` the app
  sends. A load the agent refuses as unauthenticated fails boot naming
  `CEDAR_AUTHENTICATION`. Boot warns when no token is configured.
  The token is also the boundary of what the engine can check. Policy ids
  (next) catch a set this verifier did not load: replaced, shared or
  reloaded. They do not catch a token holder who rewrites or deletes one of
  this load's policies under its own id.
- **The verifier owns the policies.** At boot the engine `PUT`s the policy set
  to the agent, one entry per `.cedar` file, so the agent holds exactly
  `config/policies` and nothing is converted or mounted twice.
  - **The policy id** is the file's name without `.cedar` (`namePolicies`),
    followed by the load's mark after an `@`: the first 16 hex of the policy
    set's revision (`10-permit-eng@9f2c…`, `agentPolicyId`, #283).
  - **The mark is the revision's own digest.** Replicas loading the same files
    push the same ids. A replica with other files does not.
  - **The policies an answer names** must all be this load's: its
    determining policies, and the policy each of its errors names. The answer
    is otherwise refused as foreign (above). The determining policies are
    recorded by their file ids, the mark removed, each once; the errors stay
    the agent's text, marked ids and all, for the log.
  - **Operators see the marked ids** in the agent (`GET /v1/policies`), in
    the agent's evaluation-error strings the rule logs, and in a boot
    refusal's list of the ids sent. A decision records the file ids.

  Boot retries an unreachable agent for 10 s (a compose sibling may be a few
  hundred milliseconds behind) and then refuses to start. The error names the
  cause — `connect ECONNREFUSED …`, `getaddrinfo ENOTFOUND …`, a TLS error — or,
  when the deadline passes while an attempt is still waiting, says no answer
  came in time, with how the attempt before failed if one did. A set the agent
  refuses fails boot at once, with the agent's message.
- **One policy per file.** cedar-agent stores policies one by one, so each
  `.cedar` file — and an inline `policies` string — must hold exactly one
  policy; a file with two is refused at boot. The wasm engine accepts several
  and numbers them (`20-rules#1`), so a corpus laid out one policy per file
  runs under both and names its policies the same way under each
  ([which policies determined it](#policy-revision-which-policies-decided)).
- **One collector per agent.** `PUT /v1/policies` replaces the agent's whole
  set, so a second `CedarPolicyRuleCollector` pointed at the same agent is
  refused at boot rather than silently overwriting the first. Every loopback
  spelling of a host (`localhost`, `127.0.0.1`, `[::1]`) on one port counts as
  the same agent.
- **One agent per replica, across deploys too (#283).** That refusal is
  per process. Replicas sharing an agent overwrite each other's set, and now
  that answers carry the load's mark, the loser fails closed.
  - **During a rolling deploy:** once the first new replica pushes, every old
    replica sharing the agent denies every request a policy would permit, and
    logs it.
  - **After a rollback:** the survivors keep denying until they restart,
    because nothing re-pushes after boot.

  Run an agent per replica, as the template's sidecar does, and restart
  replicas after a rollback. Replicas with identical files push identical ids
  and do not disturb each other.
- **Connections are not capped.** The engine uses the process's global `fetch`
  dispatcher with keep-alive, so concurrent decisions map one-to-one onto
  concurrent agent connections. Each call is bounded by `verify.ruleTimeoutMs`
  and the decision by `verify.evaluateDeadlineMs`, and a batch by
  `verify.batchConcurrency`; a deployment expecting floods on the verifier
  should size the agent for that concurrency, or put a connection-limiting
  proxy in front of it.
- **An answer is bounded.** At most `maxAnswerBytes` of one answer is read,
  and held until it is parsed, for each concurrent call. Unset, it is 1 MiB —
  the default, exported as `CEDAR_ANSWER_MAX_BYTES`; there is no environment
  variable for it. A longer answer is refused rather than held for the rule
  deadline, since a process out of memory takes every route down. An answer's
  determining-policy and error lists grow with the policy set, so a large set
  can answer honestly past 1 MiB: the refusal says so, and the fix is a higher
  `maxAnswerBytes` in the collector's entry — a whole number of bytes from
  1 KiB to 256 MiB, written as a number (`maxAnswerBytes = 4194304`) or a
  numeric string, which is what a HOCON env substitution of a variable of your
  own naming delivers (`maxAnswerBytes = ${?MY_ANSWER_BYTES}`). Anything else
  — `4 MiB` unquoted is a string — refuses to start. An error's body is read
  up to the smaller of `maxAnswerBytes` and 1 MiB, since it becomes the log
  line.
- **Failure after boot is a deny.** An agent that is unreachable, answers
  non-2xx, breaks off its answer, answers more than `maxAnswerBytes`, or
  answers something that is not a decision
  makes the rule fail and log (`cedar authorization call failed`); the log
  line's `reason` names the cause, as the boot error does. An agent that is up but has
  lost the policy set — restarted, or recreated by `docker compose up` — is
  not a failure it can see: it answers "deny, no determining policy" to every
  request, which is why `onNoDeterminingPolicy = "abstain"` is refused with
  this engine; under the default it denies everything until the verifier is
  restarted and pushes the set again. Each call runs under the server's
  `verify.ruleTimeoutMs` (default 2000 ms), answering `rule_timeout` when the
  agent is slower than that.
- **Two Cedar versions.** cedar-agent 0.2.2 evaluates with cedar-policy
  2.5.0. The agent does not report it; the version is read from the crate
  path compiled into the image's binary. The wasm package evaluates with the
  Cedar 4 release it pins (see [Version pinning](#version-pinning)).
  - Policies written to the older grammar run under both. A policy using a
    newer construct is refused by the agent at boot, which is the right place
    to find out.
  - Both are measured over one corpus (#284, see
    [Version pinning](#version-pinning)). Measured on cedar-policy 2.5.0 and
    4.13.0, they agree on every decision, every determining policy and every
    erroring policy of it, and the suite fails if they stop agreeing. Only the
    wording of error messages differs, for the same missing attribute:
    `` `User::"alice"` does not have the attribute `dept` `` under 4.13.0,
    `` `User::"alice"` does not have the attribute: dept `` under 2.5.0.
- **The response contract is cedar-agent 0.2.x's.** `POST /v1/is_authorized`
  must answer `{ decision, diagnostics: { reason: [...], errors: [...] } }`;
  an answer missing either list is refused, and the call denies. The errors
  are read as text, so an agent on a newer Cedar that reports structured errors
  still has its errors seen (and denied on), rather than every answer refused
  as malformed. The reason items are read as policy ids: a string, or an object
  with a `policyId`. Each error is read for the policy it names:
  - in a string, the id after `` error occurred while evaluating policy ` ``
    (Cedar 2.5, as cedar-agent 0.2.2 words it) or
    `` error while evaluating policy ` `` (4.x). Cedar prints it escaped, as
    Rust's `escape_debug` does (a quote, a backslash, an invisible
    character), so it is unescaped to compare. One of this load's ids is read
    to where the load's mark ends it, since a backtick in a file name is not
    escaped; any other, to the first `` `: ``;
  - in a structured error, its `policyId`.

  Cedar 2.5's one error that names no policy,
  `error occurred while evaluating entity attributes: …`, says nothing of
  which set answered, and is left out of it.

  An item in any other shape cannot be attributed to this load, so the answer
  is refused as foreign, logged `"unreadable policy"` (#283). An agent image
  that changed the shape of its reason items would deny every permit, and one
  that changed how it words its errors would have every erroring answer logged
  as foreign rather than as an evaluation error — loudly, and saying why,
  either way. Both deny.
- **Entities travel inline, and the agent reads them.** Each call carries the
  request's entities in `entities`; nothing is written to the agent's own
  `/v1/data` store. #225 left open whether cedar-agent honours inline entities
  rather than its store; the v0.10.0 release audit confirmed it against the
  pinned `permitio/cedar-agent:0.2.2`: a policy reading an inline attribute
  decides on it as the wasm engine does, and one reading an attribute the
  entity lacks answers `Deny` with the error in `diagnostics.errors`, which the
  rule denies on.

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
exactly (the version is in its [`package.json`](../cedar-wasm/package.json)),
because Cedar minor releases can carry policy-language changes and
upgrades should be deliberate. This package depends on no evaluator.

That this collector computes what Cedar computes is measured, not assumed.
The CLI-equivalence suite (#198,
[`cedar-cli-equivalence.test.mts`](../../tests/integration/src/cedar-cli-equivalence.test.mts))
runs a fixture corpus through the collector over the wasm engine and through
the official `cedar` CLI at the pinned version, asking the CLI exactly the
request the collector built.
- The engine's answer and the CLI's must be one answer: the same decision, the
  same determining policies and the same erroring policies.
- The request the collector built must be the one each case records.
- The collector must fail closed on an error, even where Cedar allows on
  another permit.

Each fixture policy carries `@id` with the id its file gives it. The CLI names
a policy by `@id`, and otherwise by its position in the whole set, not by
file. So both evaluators answer in the same names.

The `http` engine is measured by the same suite, against a real cedar-agent
(#284). It is held to the CLI of the Cedar that agent runs, 2.5.0 in the image
the template pins, rather than to the wasm engine's CLI.
- **Across the two Cedars.** Each case states its answers once, and each
  half holds its CLI to them. So every case is also measured across the
  agent's Cedar and the wasm pin (2.5.0 and 4.13.0 today): a case that meant
  one thing under one and another under the other fails on one side. The wording of error messages differs between
  them, which is why each engine is held to its own version's CLI.
- **What the agent cannot run, declared and checked.**
  - A case whose set cedar-agent refuses states why, in its `case.json`
    (`agentRefuses`). Today that is one case, whose file holds several
    policies, while the agent stores one per id. The http half checks that the
    agent does refuse it at boot. It still holds the CLI of the agent's Cedar
    to the case's answers, asked the requests the case records. A case that
    stops being refused, or starts, fails.
  - A case under `onNoDeterminingPolicy = "abstain"` runs over the agent under
    `"deny"`, and says so in its name, since `"abstain"` is refused with this
    engine. Cedar's answer does not depend on that setting, and the
    collector's reading of it under `"abstain"` is checked on the wasm side.
- **Where it runs.** CI's `cedar-agent-equivalence` job starts the image the
  template's compose pins and reads the Cedar version from its binary. It
  then installs `cedar-policy-cli` at that version and runs the suite. Bumping
  the image moves the CLI with it.
- **Running it locally.** Start the agent the template pins, with a token,
  install the CLI of its Cedar, and point the suite at both.
  - `CEDAR_AGENT_ENDPOINT`, `CEDAR_AGENT_CLI` and `CEDAR_AGENT_CEDAR_VERSION`
    go together. With none of them set, the http half is skipped, with a
    notice; with only some, it fails. An empty one counts as unset.
  - The token, `CEDAR_AGENT_AUTHENTICATION`, is not one of the three: set it
    to the token the agent was started with, or leave it unset for an agent
    without one. The suite reads only `CEDAR_AGENT_*`; `CEDAR_ENDPOINT` and
    `CEDAR_AUTHENTICATION` are ignored, whatever the engine's own hint says.
  - The version below is the one read from the image the template pins today;
    the CI job reads it afresh.
  - `--locked` holds the crate's dependencies, not the compiler, so the
    toolchain is the one CI builds it with.
  - The agent listens on every interface inside its container, as in CI,
    and is published on the host's loopback only.

  ```sh
  TOKEN=$(openssl rand -hex 32)
  IMAGE=$(grep -oE 'permitio/cedar-agent:[^[:space:]]+' templates/standalone/docker-compose.yml)
  docker run -d --name cedar-agent -p 127.0.0.1:8180:8180 \
    -e CEDAR_AGENT_ADDR=0.0.0.0 -e CEDAR_AGENT_PORT=8180 \
    -e CEDAR_AGENT_AUTHENTICATION="$TOKEN" "$IMAGE"
  rustup toolchain install 1.95.0 --profile minimal
  cargo +1.95.0 install cedar-policy-cli --locked --version 2.5.0 --root ~/.cedar-agent-cli
  pnpm run build
  CEDAR_AGENT_ENDPOINT=http://127.0.0.1:8180 CEDAR_AGENT_AUTHENTICATION="$TOKEN" \
    CEDAR_AGENT_CLI=~/.cedar-agent-cli/bin/cedar CEDAR_AGENT_CEDAR_VERSION=2.5.0 \
    pnpm --filter @o3co/auth.policy-verifier.integration-tests \
    exec vitest run cedar-cli-equivalence
  ```
