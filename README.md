# auth.policy-verifier

[![CI](https://github.com/o3co/auth.policy-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.policy-verifier/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/auth.policy-verifier.core)](https://www.npmjs.com/package/@o3co/auth.policy-verifier.core)
[![codecov](https://codecov.io/gh/o3co/auth.policy-verifier/graph/badge.svg)](https://codecov.io/gh/o3co/auth.policy-verifier)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> This repository handles **authorization decision** in the three-layer separation of concerns ([authentication & token issuance](https://github.com/o3co/auth.provider) / authorization decision / [authorization enforcement](https://github.com/o3co/protobuf.interceptors)) of the [auth](https://github.com/o3co/auth) stack.

Attribute-based access control (ABAC) engine for microservice authorization. Receives a JWT + resource + action, evaluates collector-driven rules, and returns allow/deny. No policy DSL — authorization logic is composed in TypeScript.

- Drop-in replaceable with OPA or Cedar — [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) can route to this service, OPA, or Cedar Agent via a common `VerifierEndpoint` interface
- Runs as an HTTP sidecar — swapping engines is a config change, not a code change
- Configurable JWT verification — HS256, RS256, ES256, EdDSA with JWKS or direct public key

## How It Works

```text
POST /verify
Authorization: Bearer <jwt>
{"resource": "project:1", "action": "read"}

  ┌──────────────────────────────────────────────────┐
  │                  /verify handler                  │
  │                                                   │
  │  1. Verify JWT (HS256 / RS256 / ES256 / EdDSA)   │
  │                                                   │
  │  2. AttributeCollectors (parallel)                │
  │     ├─ PayloadScopeCollector → scopes from JWT    │
  │     ├─ PayloadSubjectIdCollector → subject ID     │
  │     └─ (custom collectors...)                     │
  │                                                   │
  │  3. RuleCollectors (parallel)                     │
  │     ├─ ResourceActionScopeRuleCollector           │
  │     │   → HasScope("read:project")                │
  │     └─ (custom rule collectors...)                │
  │                                                   │
  │  4. Evaluate                                      │
  │     OR within rule group, AND across groups        │
  │     every group runs → structured reason           │
  │                                                   │
  │  → 200 {"decision": "allow",  "reason": {...}}    │
  │  → 403 {"decision":"deny","code":…,"reason":{…}} │
  └──────────────────────────────────────────────────┘

POST /verify/batch — the same contract, N decisions per round trip
{"decisions": [{"resource": "project:1", "action": "read"}, …]}
  → 200 {"decisions": [{…}, …]}   (order preserved; 200 even if all deny)
```

## Features

- **Collector pattern** — Attributes and rules are gathered by composable collectors, not a static policy file. Add custom collectors for any attribute source (database, external API, JWT claims).
- **A decision contract, not a boolean** — every request is `(subject, resource, action, context)` and every answer carries a structured `reason` naming each rule group and how it came out, so "why was this denied" is answerable without re-running the pipeline. `POST /verify/batch` decides many resources in one round trip.
- **Configurable JWT verification** — HS256 (shared secret), RS256/ES256/EdDSA (JWKS URI or direct public key). Symmetric design with [auth.provider](https://github.com/o3co/auth.provider)'s JWT config.
- **RFC 9068 §4 token validation** — `iss`, `aud` and the `typ` header are checked alongside the signature, so an `id_token`, refresh token or logout token signed with the same key, or a token minted for another service, is rejected. `issuer` and `audience` are required whenever `mode = "verify"` (the default).
- **Bounded token lifetime** — `exp` and `iat` are **required**, not merely honoured when present, and `maxTokenAgeSeconds` caps how long after issuance a token is accepted whatever `exp` its issuer chose. A token minted or forged without an expiry is refused rather than accepted forever. `clockToleranceSeconds` (0 by default, capped at 300) is the skew allowance. Every one of these applies in `insecure-decode` mode too, so the two modes never disagree about the same token.
- **JWKS support** — Point `jwksUri` at auth.provider's `https://.../.well-known/jwks.json` for automatic key rotation. The endpoint must be TLS-protected (loopback hosts excepted for local development), and the fetch is bounded by an operator-set timeout, cooldown and cache age so a provider outage cannot stall the decision path.
- **Answerable in production** — one structured `decision` event per decision (subject, resource, action, the rule that decided, request id, latency) and a Prometheus `/metrics` endpoint with allow/deny counters. Every metric label is bounded; the bearer token, the claim set beyond `sub`, and the caller's `context` never reach the log. See [Observability](#observability).
- **Pluggable architecture** — Module system for registering custom collectors, rules, and resource parsers via factories.
- **No DSL lock-in** — Authorization logic is TypeScript. No Rego, no Cedar policy language. If you outgrow this, swap to OPA or Cedar via [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — the interceptor abstracts over the backend.

## When to choose this

- Policy authors are developers, and you don't want to learn a DSL → **this**
- Policies are edited by non-developers, or you need formal verification → **[Cedar](https://www.cedarpolicy.com/)**
- You need org-wide policy infrastructure with a large built-in operator surface → **[OPA](https://www.openpolicyagent.org/)**

## Quick Start

```bash
npx @o3co/create-auth-policy-verifier my-policy-verifier
cd my-policy-verifier
pnpm install
OAUTH_JWT_SECRET=$(openssl rand -hex 32) \
  OAUTH_JWT_ISSUER=https://issuer.example.com \
  OAUTH_JWT_AUDIENCE=https://api.example.com \
  pnpm start
```

The HS256 secret must carry at least **32 bytes (256 bits)** of key material or the process refuses to boot — see [Rotating the HS256 secret](#rotating-the-hs256-secret). Use the same value auth.provider signs with.

```bash
curl -X POST http://localhost:3000/verify \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"resource": "project:1", "action": "read"}'
```

```json
{
  "subject": "user-1",
  "resource": "project:1",
  "action": "read",
  "decision": "allow",
  "reason": {
    "groups": [
      {
        "ruleType": "scope",
        "passed": true,
        "evaluated": [{ "code": "invalid_scope", "message": "…", "passed": true }],
        "satisfiedBy": { "code": "invalid_scope", "message": "…", "passed": true }
      }
    ]
  }
}
```

Filtering a list is one round trip, not one per resource:

```bash
curl -X POST http://localhost:3000/verify/batch \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"decisions": [
        {"resource": "project:1", "action": "read"},
        {"resource": "project:2", "action": "read"}
      ]}'
```

```json
{"decisions": [{ "resource": "project:1", "decision": "allow", "…": "…" }]}
```

## Architecture

```text
standalone → server   → core
          → builtins  → core
```

- **core** — Types, `evaluate()`, `AttributePipeline`, `RulePipeline`, Module infrastructure. No runtime dependencies.
- **builtins** — Built-in collectors (scope, permission, role, subject ID), rules (HasScope, HasPermission, attribute comparison rules), DotNotation resource parser. Does not depend on server. See [`docs/extending.md`](docs/extending.md) for writing custom rules and collectors.
- **server** — Express HTTP server, `createApp()`, `POST /verify` route, JWT key resolution, config schema. Does not depend on builtins.
- **standalone** — Composition root: reads HOCON config, selects modules, starts the server.

## Packages

| Package | npm | Description |
| --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth.policy-verifier.core` | Types, evaluate, pipelines, Module infrastructure |
| [`packages/builtins`](packages/builtins/) | `@o3co/auth.policy-verifier.builtins` | Built-in collectors, rules, resource parser |
| [`packages/server`](packages/server/) | `@o3co/auth.policy-verifier.server` | Express server, `createApp`, `POST /verify`, JWT key resolver |
| [`templates/standalone`](templates/standalone/) | — | Deployable server template (composition root) |
| [`create-app`](create-app/) | `@o3co/create-auth-policy-verifier` | CLI scaffolder |

## Evaluation Logic

Rules are grouped by `ruleType` (e.g., "scope", "permission"):

- **Within a group:** OR — any single passing rule satisfies the group
- **Across groups:** AND — every group must be satisfied

Every group is evaluated, including groups after the first failing one, and the
decision carries a `reason` listing each group, whether it passed, and — as
`evaluated` — every rule that actually ran in that group, in order. A passing
group stops at its first passing rule and names it again as `satisfiedBy`; a
failing group ran every alternative. Stopping at the first failure cannot say
which of the remaining groups would also have failed, which is the question a
deny explanation exists to answer. Rules are pure predicates over attributes by
contract, so running them all is safe. The `code` / `message` on a deny still
come from the first failing group, unchanged.


Empty rule set → **deny**. A request that collects no rule was never authorized by anything, so the
engine denies it with `no_applicable_rule` — matching the implicit-deny semantics of OPA / OpenFGA /
Cedar. `rule.onEmptyRuleSet = "allow"` is an explicit per-deployment opt-out that makes the engine
fail-open; set it only when authorization is enforced elsewhere. Booting with no rule collector
configured at all is rejected.

### Built-in Rule Types

| Rule | Generated by | Matches |
| --- | --- | --- |
| `HasScope("read:project")` | `ResourceActionScopeRuleCollector` | JWT `scope` claim contains `read:project` |
| `HasPermission("project:1.perm:read")` | `ResourceActionPermissionRuleCollector` | User permissions/roles include matching pattern (supports `*` wildcards) |

A rule collector is only half a policy: groups are ANDed, so one enabled without
the attribute collector that feeds it is a group nothing can satisfy — a verifier
that denies every request. Pair `ResourceActionPermissionRuleCollector` with a
collector writing `permissions` / `roles` in the same edit.

### Built-in Attribute Collectors

| Collector | Reads | Writes |
| --- | --- | --- |
| `PayloadScopeCollector` | JWT `scope` claim | `scopes` |
| `PayloadSubjectIdCollector` | JWT `sub` claim | `userId` |
| `StaticPermissionCollector` / `StaticRoleCollector` | config constants | `permissions` / `roles` |
| `RequestContextAttributeCollector` | declared fields of the request `context` | the operator's own keys |

## Configuration

HOCON config with environment variable overrides:

```hocon
http {
  port = 3000
  port = ${?HTTP_PORT}
}

oauth {
  jwt {
    algorithm = "HS256"           # HS256 | RS256 | ES256 | EdDSA
    algorithm = ${?OAUTH_JWT_ALGORITHM}

    # ---- HS256 only. Keep exactly one of these two groups. --------------
    secret = ${?OAUTH_JWT_SECRET}            # >= 32 decoded bytes — `openssl rand -hex 32`
    kid = ${?OAUTH_JWT_KID}                  # names the secret above; unset means the token header is not consulted
    # previousSecrets — retired secrets still inside their overlap window,
    # max 3. Omitted here on purpose: the key is REFUSED at boot under
    # RS256/ES256/EdDSA, an empty list included, so it must not sit in a
    # snippet meant to be copied for any algorithm. Add it only under HS256:
    #   previousSecrets = [
    #     { kid = "v0", secret = ${?OAUTH_JWT_PREVIOUS_SECRET}, expiresAt = "2026-09-01T00:00:00Z" }
    #   ]

    # ---- RS256 / ES256 / EdDSA only -------------------------------------
    jwksUri = ${?OAUTH_JWT_JWKS_URI}         # https required, e.g. https://auth-provider/.well-known/jwks.json
    jwksTimeoutMs = 5000                     # JWKS fetch bounds — abort after
    jwksCooldownMs = 30000                   # minimum spacing between fetches
    jwksCacheMaxAgeMs = 600000               # cache lifetime of a fetched JWKS
    publicKey = ${?OAUTH_JWT_PUBLIC_KEY}     # PEM string
    publicKeyPath = ${?OAUTH_JWT_PUBLIC_KEY_PATH}  # or file path

    # ---- every algorithm -------------------------------------------------
    issuer = ${?OAUTH_JWT_ISSUER}           # required when mode = "verify" — RFC 9068 §4 iss
    audience = ${?OAUTH_JWT_AUDIENCE}       # required when mode = "verify" — RFC 9068 §4 aud
    tokenType = "at+jwt"                     # accepted typ header
    tokenType = ${?OAUTH_JWT_TOKEN_TYPE}
    maxTokenAgeSeconds = 86400               # ceiling on now - iat; makes iat required
    clockToleranceSeconds = 0                # skew allowance, 0–300; 60 matches the provider
    mode = "verify"                          # "verify" (default) | "insecure-decode" (test-only)
    mode = ${?OAUTH_JWT_MODE}
  }
}

attribute {
  collectors = [
    { collector = "PayloadScopeCollector" }
    { collector = "PayloadSubjectIdCollector" }
    # Promotes declared fields of the request body's `context` into attributes.
    # Nothing undeclared is promoted, and a value that does not match its
    # declared type is dropped.
    { collector = "RequestContextAttributeCollector"
      attributes = [
        { from = "tenant.id", to = "tenantId" }
        { from = "groups", type = "string[]" }
      ] }
  ]
}

rule {
  onEmptyRuleSet = "deny"       # deny | allow — decision when no rule is collected
  onEmptyRuleSet = ${?RULE_ON_EMPTY_RULE_SET}
  collectors = [
    { collector = "ResourceActionScopeRuleCollector" }
  ]
}

resource {
  parser = DotNotationResourceParser
}

verify {
  maxBatchSize = 50             # cap on POST /verify/batch entries
  maxBatchSize = ${?VERIFY_MAX_BATCH_SIZE}
  maxBodyBytes = 65536          # JSON body ceiling; over it → 413 payload_too_large
  maxBodyBytes = ${?VERIFY_MAX_BODY_BYTES}
  maxResourceLength = 512       # characters in `resource`
  maxResourceLength = ${?VERIFY_MAX_RESOURCE_LENGTH}
  maxActionLength = 64          # characters in `action`
  maxActionLength = ${?VERIFY_MAX_ACTION_LENGTH}
  maxContextEntries = 64        # properties + array elements in `context`, at every depth
  maxContextEntries = ${?VERIFY_MAX_CONTEXT_ENTRIES}
  maxContextValueLength = 1024  # characters in any `context` string, keys included
  maxContextValueLength = ${?VERIFY_MAX_CONTEXT_VALUE_LENGTH}
}
```

### Request Limits

Every input a caller controls is bounded, and each bound is one of the knobs above. `maxBodyBytes`
is the outer envelope — `express.json()`'s limit, below Express's unstated 100 KB default — and it
is what binds first on a large batch, since the per-field limits bound *one* entry rather than N of
them. `maxContextEntries` counts every property and every array element in the whole `context`
tree, so nesting is bounded rather than forbidden (`RequestContextAttributeCollector` reads dot
paths such as `tenant.id`); because each level of nesting costs at least one entry, it bounds the
depth too.

Three refusals are worth stating outright:

- **Whitespace in `resource` or `action` is refused, not trimmed** — the doctrine the resource
  grammar already applies, extended to `action` and to a deployment that registered its own parser.
  Both are concatenated into the `{action}:{resourceType}` scope an issuer has to have granted, and
  RFC 6749 §3.3 makes space the delimiter between scope values.
- **Unknown properties are refused** — `{"resource": "project:1", "action": "read", "subject": "admin"}`
  is `400 invalid_request` rather than a decision with the `subject` quietly ignored. The subject
  comes from the verified token and never from the body; refusing is how a caller finds that out.
- **The body is validated before the token is verified**, so a malformed request is `400` whether or
  not a token was presented. The body checks are bounded by the limits above, while verifying a
  token is the half that can reach the network. An anonymous caller therefore learns whether a body
  was well-formed; `http.callerAuth` is the gate for a deployment that must not disclose even that.

A body the parser itself refuses answers the same deny envelope as everything else — the endpoint
never falls back to Express's HTML error page:

```json
{"decision": "deny", "code": "invalid_request", "message": "Request body is not valid JSON"}
```

That is `400` for malformed JSON, `413 payload_too_large` over `maxBodyBytes`, and
`415 unsupported_media_type` for a content type or charset it cannot read. The example above is the
response body verbatim; `verifyInputValidation.test.mts` asserts that this exact line appears in
`README.md`, `README.ja.md` and `CHANGELOG.md` and parses to what the endpoint emits, so the three
copies cannot drift from the code or from each other.

### Resource String Format (DotNotation)

```text
"project:1"               → resourceType: "project",         resourceId: "1"
"project:1.member:2"      → resourceType: "project.member",  resourceId: "2"
"project:1.member"        → resourceType: "project.member",  resourceId: undefined
"project_member:2"        → resourceType: "project_member",  resourceId: "2"
```

The grammar is `segment *( "." segment )` where `segment = type [ ":" id ]`, and a type or id is one
or more characters of RFC 6749 `NQCHAR` less `.` and `:` (printable ASCII except space, `"`, `\`,
`.` and `:`). `resourceType` is the segment types joined with `.` — the separator is preserved, so
the nested type `a.b` and the flat type named `a_b` stay distinct.

Anything else is refused with `400 invalid_request` rather than repaired: empty segments (`a..b`),
a second `:` in a segment (`a:1:2` is not truncated to `a:1`), and surrounding or inner whitespace
(`  a:1  ` is not trimmed). `resourceType` is the authorization namespace the scope rules use, so a
parser that guessed at malformed input could hand a caller a grant written for a different resource.

## Connecting to auth.provider

When auth.provider uses asymmetric JWT signing (RS256/ES256/EdDSA), point the policy-verifier's `jwksUri` at the provider's JWKS endpoint:

```hocon
oauth.jwt {
  algorithm = "RS256"
  jwksUri = "https://auth-provider:3000/.well-known/jwks.json"
}
```

The policy-verifier fetches and caches the public keys automatically via jose's `createRemoteJWKSet`, bounded by `jwksTimeoutMs` / `jwksCooldownMs` / `jwksCacheMaxAgeMs`.

**The JWKS URI must be `https://`.** Every key that endpoint serves can verify tokens this deployment accepts, so its identity is the entire trust anchor and TLS is what establishes it; over plaintext, anyone on the network path — or holding a DNS answer — substitutes their own signing key and mints tokens that verify. Plaintext `http://` is accepted only for loopback hosts (`localhost`, `127.0.0.0/8`, `[::1]`), where there is no network path to sit on; that carve-out is for local development and tests. A service reached by container or DNS name (`http://auth-provider:3000`) is **not** loopback and is rejected at config-parse time — put a TLS terminator in front of the provider, or share the public key directly with `publicKey` / `publicKeyPath`.

For HS256, both services share the same secret:

```hocon
oauth.jwt {
  algorithm = "HS256"
  secret = ${OAUTH_JWT_SECRET}
}
```

**Every HS256 secret must carry at least 32 bytes (256 bits) of key material**, and a shorter one is refused at boot rather than at the first request. HS256 is symmetric: the value that verifies a token is the value that signs one, so guessing it is not read access, it is the ability to mint tokens for any subject. RFC 7518 §3.2 requires a key at least as wide as the hash output, and auth.provider enforces the same floor on the same value.

Generate one with `openssl rand -hex 32` (or `openssl rand -base64 32`). The measurement is on **decoded** material, at the smallest plausible reading:

| Value | Reads as | Verdict |
| --- | --- | --- |
| `openssl rand -hex 32` — 64 hex characters | 32 bytes | passes |
| `openssl rand -hex 16` — 32 hex characters | 16 bytes | refused |
| `openssl rand -base64 32` — 43 characters + `=` | 32 bytes | passes |
| 32 random alphanumerics | 24 bytes (a base64 body) | refused |
| a 32-character passphrase with punctuation | 32 bytes | passes |

Length is all this can see: a 40-character English sentence measures 40 bytes and carries far less. Generate the secret randomly; the check is a floor, not a review.

The floor applies to `secret` and to every entry of `previousSecrets` below, in one rule — a retired secret verifies for its whole overlap window, so it can mint tokens exactly as the current one can.

### Rotating the HS256 secret

Under a single shared secret there is no way to change it without an outage: the moment auth.provider signs with a new value, every token already in flight fails here until both services have restarted in lockstep. `previousSecrets` is the overlap window that removes the lockstep — the same `kid` + `secret` + `expiresAt` shape auth.provider rotates with, so one pair of values moves on both sides.

1. Generate the new secret: `openssl rand -hex 32`.
2. **Verifier first.** Add the *new* secret as a previous secret while the old one is still current, and restart. The verifier now accepts both; nothing has changed about what the provider mints.

   ```hocon
   oauth.jwt {
     algorithm = "HS256"
     kid = "v0"                 # still the secret the provider signs with
     secret = ${OAUTH_JWT_SECRET}
     previousSecrets = [{
       kid = "v1"               # the incoming secret, accepted ahead of the cutover
       secret = ${OAUTH_JWT_NEXT_SECRET}
       expiresAt = "2026-09-01T00:00:00Z"
     }]
   }
   ```

3. **Then the provider.** Move it to the new `kid`/`secret`, keeping the old pair in *its* `previousSecrets`, and restart. Tokens now arrive signed with the new secret and the verifier already accepts them.
4. **Verifier again.** Swap the roles: the new secret becomes `kid`/`secret`, the old one moves into `previousSecrets` with an `expiresAt` of your access-token TTL plus a buffer (auth.provider ships one-hour tokens). Restart.
5. Once that timestamp passes, the retired secret stops verifying on its own — no restart needed. Delete the entry from both configs at your convenience.

Notes:

- The field carries auth.provider's name, but on the verifier it means **every secret accepted besides the current one**. That is why step 2 stages the *incoming* secret there before the provider has ever signed with it: the verifier has to span the cutover from both sides, and this is the list that lets it.
- `expiresAt` is evaluated per request, so a window closes without a restart. A retired secret inside its window can still **mint** tokens for anyone holding it, which is why the window should be a token lifetime, not a quarter.
- `kid` is optional and unset means what it always meant: one secret verifies everything and the token header is never read. Setting it — which `previousSecrets` requires — starts pinning the header, and a token carrying an unconfigured `kid` is refused.
- A token that carries **no** `kid` is still accepted: it is tried against every secret configured, current and previous. That costs one signature check per secret, which is why `previousSecrets` is capped at **3** entries.
- The list is HS256-only, and **an empty `previousSecrets = []` under RS256/ES256/EdDSA is refused too** — the check is on the key being present, not on it having entries. Those algorithms rotate through the JWKS at `jwksUri`, which already carries every key the issuer publishes, so the block configures nothing and is rejected at boot rather than silently ignored. Do not leave it behind when switching a config to an asymmetric algorithm.
- `kid` is the exception: it is HS256-only in effect but *accepted and ignored* under the asymmetric algorithms, which match `kid` against the JWKS they fetch. It will not break an asymmetric boot.

## Observability

An authorization service that cannot answer "why was this request denied?" from its own output is undiagnosable during the incident it is at the centre of. Both surfaces below are on by default in `createApp`; the deployable template's [README](templates/standalone/README.md#observability) has the operator detail.

### The decision log

One structured event per decision, named `decision`, at `info`:

```json
{"msg":"decision","requestId":"6f1c…","sub":"user-42","resource":"project:7","action":"read","decision":"deny","code":"invalid_scope","deniedBy":{"ruleType":"scope","refused":["invalid_scope"]},"durationMs":0.412}
```

`satisfiedBy` replaces `deniedBy` on an allow, naming the rule that satisfied each group. A `POST /verify/batch` of N entries emits N lines sharing one `requestId`. `durationMs` is time in the pipelines and the evaluator, not the HTTP round trip.

`logging.level` (`LOG_LEVEL`) is the switch — the line is `info`, so `warn` turns the stream off, and there is no second flag. A deny is a normal outcome for a decision point rather than a fault, so it is not routed to `warn`: that would let any caller manufacture warn-level noise. Alert on the metrics, read the log for the "why".

**Never logged:** the raw bearer token, the claim set beyond `sub`, and the caller's `context` object — free-form, forwarded verbatim to collectors, and therefore exactly where a calling service's own request payload ends up.

### Metrics

`GET /metrics`, Prometheus text exposition format:

| Metric | Type | Labels |
|---|---|---|
| `auth_decisions_total` | counter | `decision` |
| `auth_denials_total` | counter | `code` |
| `auth_decision_duration_seconds` | histogram | `decision` |
| `http_request_duration_seconds` | histogram | `method`, `route`, `status` |
| `auth_policy_verifier_*` | various | Node process defaults |

`http_request_duration_seconds` matches [auth.provider](https://github.com/o3co/auth.provider)'s name and label set, so one Prometheus job covers both halves of the stack.

**Every label is bounded**, because an unbounded one mints a fresh time series per distinct value — which is how a metrics endpoint takes down the monitoring meant to watch it. `resource`, `action` and `sub` are not labels at all: they come from the request (body or token) and belong on the log line, where high cardinality is the point. `route` is the Express route pattern with unmatched requests collapsing to `route="unmatched"`; `method` is an allowlist with everything else `"other"`; `code` is capped at 32 distinct values.

**`/metrics` is not gated by `http.callerAuth`.** Prometheus scrape configs carry `authorization` / `basic_auth` / `oauth2` and no arbitrary header, so gating it on `x-caller-token` would make it unscrapable by a stock scraper and push operators into handing the credential that authorizes *decisions* to the monitoring system. The endpoint publishes counts and latencies with bounded labels and nothing about any individual decision. The boundary is the bind address, which is loopback by default (#108) — put the scraper on the host (a sidecar in the same Kubernetes pod shares the network namespace and reaches `127.0.0.1:3000/metrics` with the default untouched), and where the bind must be `0.0.0.0`, restrict the port at the network layer as you already do for `/verify`.

## Development

```bash
pnpm install
pnpm -r build    # build all packages
pnpm -r test     # test all packages
```

## Docker

```bash
npx @o3co/create-auth-policy-verifier my-verifier
cd my-verifier
docker build -t my-verifier .
docker run -p 3000:3000 \
  -e HTTP_HOSTNAME=0.0.0.0 -e HTTP_CALLER_AUTH_TOKEN=<secret> \
  -e OAUTH_JWT_SECRET=$(openssl rand -hex 32) my-verifier
```

The scaffolder generates `pnpm-lock.yaml`; the image builds with
`--frozen-lockfile` and will not build without it.

`HTTP_HOSTNAME=0.0.0.0` is required for the port to be reachable at all — the
config binds loopback by default, and the container's `HEALTHCHECK` reports
`unhealthy` when it is not set rather than pretending otherwise. Publishing the
port is also what makes `HTTP_CALLER_AUTH_TOKEN` necessary: `/verify` answers
with an authorization decision, so a reachable port with no credential answers
anyone who can route to it. See
[`templates/standalone/README.md`](templates/standalone/README.md#docker).

## Related Projects

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 provider with DID authentication
- [auth.proxy](https://github.com/o3co/auth.proxy) — Token validation reverse proxy
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — protobuf method option authorization interceptors for gRPC / ConnectRPC (calls this service for authorization decisions)
- [auth](https://github.com/o3co/auth) — Architecture docs and E2E tests

## Coverage

Per-package coverage is tracked on Codecov and broken down by flag:

- [core](https://codecov.io/gh/o3co/auth.policy-verifier?flag=core) — engine core
- [builtins](https://codecov.io/gh/o3co/auth.policy-verifier?flag=builtins) — built-in collectors and rules
- [server](https://codecov.io/gh/o3co/auth.policy-verifier?flag=server) — HTTP server layer

Run locally with `pnpm run test:coverage` to generate reports under each package's `coverage/`.

## License

Apache License 2.0 — Copyright 2026 1o1 Co. Ltd.
