# @o3co/auth.policy-verifier.server

Express HTTP server for auth.policy-verifier. Provides `createApp` to assemble the application from modules and config, and `POST /verify` / `POST /verify/batch` for authorization decisions.

## Install

```bash
npm install @o3co/auth.policy-verifier.server
```

## Public API

### createApp

```typescript
interface CreateAppOptions {
  pathResolver: PathResolver;
  config: AppConfig;
  modules: Module[];
}

function createApp(options: CreateAppOptions): Promise<express.Express>
```

Assembles and returns a configured Express application. Does not start listening — call `app.listen(...)` separately.

Steps performed:

1. Creates `Registry` instances for attribute collector, rule collector, and resource parser factories.
2. Calls `mod.init(context)` for each module in order, allowing each to register factory functions.
3. Instantiates attribute collectors and rule collectors from `config.attribute.collectors` and `config.rule.collectors` by looking up the registered factory for each `collector` name.
4. Instantiates the resource parser from `config.resource.parser`.
5. Mounts `GET /healthcheck`, the optional caller-authentication gate, then `POST /verify` and `POST /verify/batch` under `config.http.pathPrefix`.
6. Returns the configured `express.Express` instance.

`pathResolver` must be `import.meta.resolve` (or a compatible resolver) from the composition root. It is passed to modules that need to resolve module-relative paths.

### createVerifyRouter

```typescript
interface VerifyRouterConfig {
  jwt: VerifyRouterJwtConfig;
  resourceParser: ResourceParser;
  attributePipeline: AttributePipeline;
  rulePipeline: RulePipeline;
  /** Evaluator semantics overrides; omitted means deny on an empty rule set. */
  evaluateOptions?: EvaluateOptions;
  /** Most entries POST /verify/batch will decide in one request. Defaults to 50. */
  maxBatchSize?: number;
  /** How many of a batch's entries are decided at once (#183). Defaults to 8. */
  batchConcurrency?: number;
}

// Discriminated on `validate`: verification parameters exist only when verifying.
// The time-claim bounds sit on both arms, because both arms enforce them.
type JwtTimeClaimConfig = {
  maxTokenAgeSeconds?: number | string;    // ceiling on now - iat; default 86400
  clockToleranceSeconds?: number | string; // skew allowance, 0–300; default 0
};

type VerifyRouterJwtConfig =
  | (JwtTimeClaimConfig & {
      validate: true;
      key: unknown;             // from a KeyResolverFactory
      algorithms: string[];
      issuer: string | string[];    // RFC 9068 §4 iss
      audience: string | string[];  // RFC 9068 §4 aud
      tokenType: string;            // accepted typ header, e.g. "at+jwt"
    })
  | (JwtTimeClaimConfig & { validate: false; allowInsecureDecode: true });

function createVerifyRouter(config: VerifyRouterConfig): express.Router
```

Returns an Express Router that handles `POST /verify` and `POST /verify/batch`. `createApp` calls this internally; use it directly only if you need to mount the router independently.

Request flow:

1. Extract `Authorization: <type> <token>` header. Returns 401 if missing.
2. If `validate` is `true`: verify the signature **and** the RFC 9068 §4 claims — `iss` against `issuer`, `aud` against `audience`, and the `typ` header against `tokenType` (an `application/` prefix is ignored). Returns 401 on failure. `createVerifyRouter` throws if any of the three is missing.
3. If `validate` is `false`: decode the JWT without verification. Returns 401 if the token is malformed.
4. Either way, enforce the token's own lifetime: `exp` and `iat` are **required** (a token that never states an expiry never expires), `nbf` is honoured when present, `exp` must be in the future, and `now - iat` must not exceed `maxTokenAgeSeconds` — which is what refuses a token whose issuer set `exp` years out. `clockToleranceSeconds` widens every one of those comparisons. Returns 401 on failure. The decode-only path restates these checks by hand rather than skipping them, so both modes answer the same for the same token.
5. Parse `req.body.resource` with `resourceParser`; read `req.body.action` and `req.body.context`.
6. Include `x-request-id` header in `CollectorContext.headers` if present (collectors can forward it to upstream calls they make).
7. Run `attributePipeline.collect` and `rulePipeline.collect` in parallel, under the collector bounds (`verify.collectorTimeoutMs`, `verify.collectorDeadlineMs`, `verify.collectorConcurrency` — each collector is handed an `AbortSignal` on `CollectorContext.signal`); call `evaluate`.
8. Return `200 { decision: "allow" }` or `403 { decision: "deny", code, message }`.
9. Return `403 { decision: "deny", code: "collector_timeout" }` when a collector or the fan-out ran out of time (#115). The evaluator is never reached — collecting *some* of the rules is a weaker policy, and none of them is an allow under `rule.onEmptyRuleSet = "allow"` — so a timeout can only ever deny. Details go to the `collector_timeout` log line, not to the caller.
10. Return `500 { decision: "deny", code: "internal_error" }` on unexpected errors.

### AppConfigSchema / AppConfig

```typescript
const AppConfigSchema = z.object({
  http: z.object({
    hostname: z.string().default("127.0.0.1"),   // loopback — see Trust boundary
    port: boundedNumber(NUMERIC_BOUNDS.port, "http"),               // 1..65535, default 3000
    pathPrefix: z.string().default(""),
    callerAuth: z.object({                        // optional — see Trust boundary
      header: z.string().min(1).default("x-caller-token"),
      token: z.string().min(1).optional(),
    }).optional(),
  }),
  oauth: z.object({
    jwt: z.object({
      secret: z.string().optional(),                                   // HS256: >= 32 decoded bytes
      mode: z.enum(["verify", "insecure-decode"]).default("verify"),
      issuer: z.union([z.string(), z.array(z.string())]).optional(),   // required when mode is "verify"
      audience: z.union([z.string(), z.array(z.string())]).optional(), // required when mode is "verify"
      tokenType: z.string().default("at+jwt"),
      maxTokenAgeSeconds: boundedNumber(NUMERIC_BOUNDS.maxTokenAgeSeconds, "oauth.jwt"),
      clockToleranceSeconds: boundedNumber(NUMERIC_BOUNDS.clockToleranceSeconds, "oauth.jwt"),
    }),
  }),
  attribute: z.object({
    collectors: z.array(z.object({ collector: z.string() }).passthrough()),
  }),
  rule: z.object({
    collectors: z.array(z.object({ collector: z.string() }).passthrough()),
  }),
  resource: z.object({
    parser: z.string().default("DotNotationResourceParser"),
  }),
  verify: z.object({
    maxBatchSize: boundedNumber(NUMERIC_BOUNDS.maxBatchSize, "verify"),           // default 50
    // What one decision request may carry (#118).
    maxBodyBytes: boundedNumber(NUMERIC_BOUNDS.maxBodyBytes, "verify"),           // default 65536
    maxResourceLength: boundedNumber(NUMERIC_BOUNDS.maxResourceLength, "verify"), // default 512
    maxActionLength: boundedNumber(NUMERIC_BOUNDS.maxActionLength, "verify"),     // default 64
    maxContextEntries: boundedNumber(NUMERIC_BOUNDS.maxContextEntries, "verify"), // default 64
    maxContextValueLength:
      boundedNumber(NUMERIC_BOUNDS.maxContextValueLength, "verify"),              // default 1024
    // Bounds on the collector fan-out (#115). Exceeding any of them denies.
    collectorTimeoutMs: boundedNumber(NUMERIC_BOUNDS.collectorTimeoutMs, "verify"),   // default 2000
    collectorDeadlineMs: boundedNumber(NUMERIC_BOUNDS.collectorDeadlineMs, "verify"), // default 5000
    collectorConcurrency:
      boundedNumber(NUMERIC_BOUNDS.collectorConcurrency, "verify"),               // default 8
    // How many of a batch's entries are decided at once (#183). The collector
    // bounds are per decision; this bounds their product with the batch.
    batchConcurrency: boundedNumber(NUMERIC_BOUNDS.batchConcurrency, "verify"),   // default 8
  }),
});

type AppConfig = z.infer<typeof AppConfigSchema>;
```

**Every numeric knob is read by one function at both boundaries** (#157). `boundedNumber` wraps
`resolveBound` from [`config/bounds.mts`](src/config/bounds.mts), where `NUMERIC_BOUNDS` states each
knob's default, range and unit once; the runtime guards (`createApp`, `createVerifyRouter`, the
`KeyResolverFactory` implementations) call `resolveBound` directly for hand-built configs, so both
reach the same verdict in the same words. It is deliberately **not** `z.coerce.number()`: a knob
arrives either as a number or as the string a HOCON `${?VAR}` substitution delivers, and both are
accepted — but `z.coerce` would also read `true` as `1`, `null` and `""` as `0`, which is how a
variable exported empty used to become a deliberate zero. Non-integers, `NaN` and `Infinity` are
refused for the same reason.

Each entry in `attribute.collectors` and `rule.collectors` requires a `collector` field (the registered factory name). Additional fields are passed through to the factory as configuration.

**HS256 secrets must carry at least 32 bytes (256 bits) of key material.** The floor applies to `oauth.jwt.secret` and to every `oauth.jwt.previousSecrets[].secret` in one rule, since a retired secret verifies for its whole overlap window and can mint tokens exactly as the current one can. It is measured on decoded material at the smallest plausible reading, so 64 hex characters pass (32 bytes) and 32 hex characters do not (16 bytes); generate one with `openssl rand -hex 32`. `AppConfigSchema` rejects a short secret at config-parse time and the HS256 `KeyResolverFactory` repeats the check for hand-built configs. `measureSecretEntropyBytes` / `describeWeakSecret` / `MIN_SECRET_ENTROPY_BYTES` are exported for consumers registering their own HS256 key resolver; `createVerifyRouter` takes key material directly and does not apply the floor, so a caller wiring a `KeyObject` by hand owns that check.

### Trust boundary

The bearer token on `/verify` establishes the **subject** a decision is about. It says nothing about which service supplied `resource` / `action` / `context`. An endpoint that checks only the subject token is therefore a decision oracle: anyone who can route to the port can probe which tokens, scopes and resources the deployment accepts, and make it run collector pipelines while they do.

Two settings bound that exposure:

- **`http.hostname` defaults to `127.0.0.1`.** The deployment this project targets is a sidecar — the enforcement layer runs alongside the verifier and reaches it over loopback. Binding all interfaces is an explicit opt-in (`http.hostname = "0.0.0.0"`), which a containerised deployment must set to be reachable at all.
- **`http.callerAuth.token` authenticates the calling service.** When set, every request to `/verify` and `/verify/batch` must carry that credential verbatim in `http.callerAuth.header` (default `x-caller-token`, deliberately not `Authorization`). The comparison is constant-time, and it runs before the body is parsed and before any pipeline work, so an unauthenticated peer costs the process nothing. A missing credential and a wrong one get the same `401 { decision: "deny", code: "caller_unauthenticated", message: "Caller authentication failed" }` — the rejection must not tell a prober whether their guess had the right shape. `GET /healthcheck` is never gated, so orchestrator probes keep working.

Caller authentication is **optional in this release**. When it is not configured and the bind is not loopback, `createApp` logs `unauthenticated_non_loopback_bind` at warn — the genuinely dangerous combination, named rather than blocked. Making it mandatory is a one-line change to `CALLER_AUTH_REQUIRED` in `config/defaults`; see that constant's doc comment.

A shared credential is not a substitute for network policy or mTLS between the enforcement layer and this service. It is the floor, not the ceiling.

### POST /verify

**Request**

```http
POST /verify HTTP/1.1
Authorization: Bearer <jwt>
Content-Type: application/json
x-request-id: <optional>

{
  "resource": "project:1",
  "action": "read",
  "context": {}
}
```

`subject` is **not** accepted in the body. It comes from the verified token's `sub` claim — accepting one here would let any token holder ask for a decision about somebody else.

**Response — allow**

```http
HTTP/1.1 200 OK

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
        "evaluated": [{ "code": "invalid_scope", "message": "...", "passed": true }],
        "satisfiedBy": { "code": "invalid_scope", "message": "...", "passed": true }
      }
    ]
  }
}
```

**Response — deny**

```http
HTTP/1.1 403 Forbidden

{
  "subject": "user-1",
  "resource": "project:1",
  "action": "read",
  "decision": "deny",
  "code": "<code>",
  "message": "<message>",
  "reason": { "groups": [ ... ] }
}
```

`reason.groups` lists every rule group in evaluation order — `passed`, plus `evaluated`: every rule that actually ran in that group, in order. A failing group ran (and lists) every alternative; a passing group stops at its first passing rule, so `evaluated` ends with it after any alternatives that were tried and failed, and `satisfiedBy` — present only on a passing group, absent on a failing one — names that deciding rule explicitly. `code` / `message` come from the first failing group, as before.

**Response — malformed request**

```http
HTTP/1.1 400 Bad Request

{ "decision": "deny", "code": "invalid_request", "message": "<message>" }
```

Returned when `resource` or `action` is missing, empty or not a string, when `context` is not an
object, and when `resource` is a string the configured `ResourceParser` refuses — a syntax error in
the caller's request, not a server fault, so it is answered 400 rather than 500 and is not logged as
`verify_internal_error`. For `DotNotationResourceParser` that covers empty segments (`a..b`), a
second `:` in a segment (`a:1:2`), and whitespace (`  a:1  `); see the
[builtins README](../builtins/README.md#dotnotationresourceparser) for the grammar. The body is
validated before any decision is made, so nothing is evaluated for a request that is refused here.

**Response — unexpected error**

```http
HTTP/1.1 500 Internal Server Error

{ "decision": "deny", "code": "internal_error" }
```

### POST /verify/batch

The same decision contract, N decisions per round trip — filtering a list of N resources costs one request rather than N.

**Request**

```http
POST /verify/batch HTTP/1.1
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "decisions": [
    { "resource": "project:1", "action": "read" },
    { "resource": "project:2", "action": "read", "context": { "tenant": "acme" } }
  ]
}
```

One token authorizes the whole batch; each entry carries its own `resource`, `action` and `context`.

**Response**

```http
HTTP/1.1 200 OK

{ "decisions": [ { ... }, { ... } ] }
```

Entries come back in request order, each the same object `POST /verify` would have answered for it. The status reports whether the batch was **decided**, not what it decided — a batch of denials is still `200`, and the caller reads each entry. Entries are decided at most `verify.batchConcurrency` (default 8) at a time (#183): the collector bounds are per decision, so this is what keeps one batch from holding `maxBatchSize × collectorConcurrency` collectors in flight per pipeline. `400 invalid_request` when `decisions` is absent, empty, over `verify.maxBatchSize`, or carries a malformed entry — including one whose `resource` the parser refuses — with the message naming the index; `401` rejects the whole batch when the token does not verify. The whole batch is validated before any of it is decided, so one bad entry refuses the request rather than yielding a partial answer.

## Usage Example

```typescript
import { resolve } from 'node:path'
import { parseFile } from '@o3co/ts.hocon'
import { validate } from '@o3co/ts.hocon/zod'
import {
  createApp,
  AppConfigSchema,
  builtinKeyResolversModule,
} from '@o3co/auth.policy-verifier.server'
import { builtinCollectorsModule } from '@o3co/auth.policy-verifier.builtins'

const config = validate(
  parseFile(resolve(import.meta.dirname, '../config/application.conf')),
  AppConfigSchema,
)

const app = await createApp({
  pathResolver: import.meta.resolve,
  config,
  modules: [builtinCollectorsModule, builtinKeyResolversModule],
})

app.listen(config.http.port, config.http.hostname, () => {
  console.log(`listening on ${config.http.hostname}:${config.http.port}`)
})
```

To add a custom module, implement `Module` from `@o3co/auth.policy-verifier.core` and pass it in the `modules` array:

```typescript
import type { Module } from '@o3co/auth.policy-verifier.core'

const customModule: Module = {
  name: 'custom',
  async init(context) {
    context.attributeCollectorRegistry.register(
      'MyRoleCollector',
      (config) => new MyRoleCollector(config),
    )
  },
}

const app = await createApp({
  pathResolver: import.meta.resolve,
  config,
  modules: [builtinCollectorsModule, builtinKeyResolversModule, customModule],
})
```

`builtinKeyResolversModule` registers HS256 / RS256 / ES256 / EdDSA factories into the `keyResolverRegistry`. Compose it alongside your custom modules; omit it only if you provide your own key resolver module.

## See Also

- [`@o3co/auth.policy-verifier.core`](../core/README.md) — Types, `evaluate`, `AttributePipeline`, `RulePipeline`, Module infrastructure
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.md) — Built-in collectors and parsers
- [auth.policy-verifier root README](../../README.md) — Architecture overview, configuration reference, Docker
