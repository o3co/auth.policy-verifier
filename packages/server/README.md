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
5. Mounts `GET /healthcheck`, `POST /verify` and `POST /verify/batch` under `config.http.pathPrefix`.
6. Returns the configured `express.Express` instance.

`pathResolver` must be `import.meta.resolve` (or a compatible resolver) from the composition root. It is passed to modules that need to resolve module-relative paths.

### createVerifyRouter

```typescript
interface VerifyRouterConfig {
  jwt: VerifyRouterJwtConfig;
  resourceParser: ResourceParser;
  attributePipeline: AttributePipeline;
  rulePipeline: RulePipeline;
}

// Discriminated on `validate`: verification parameters exist only when verifying.
type VerifyRouterJwtConfig =
  | {
      validate: true;
      key: unknown;             // from a KeyResolverFactory
      algorithms: string[];
      issuer: string | string[];    // RFC 9068 §4 iss
      audience: string | string[];  // RFC 9068 §4 aud
      tokenType: string;            // accepted typ header, e.g. "at+jwt"
    }
  | { validate: false };

function createVerifyRouter(config: VerifyRouterConfig): express.Router
```

Returns an Express Router that handles `POST /verify` and `POST /verify/batch`. `createApp` calls this internally; use it directly only if you need to mount the router independently.

Request flow:

1. Extract `Authorization: <type> <token>` header. Returns 401 if missing.
2. If `validate` is `true`: verify the signature **and** the RFC 9068 §4 claims — `iss` against `issuer`, `aud` against `audience`, and the `typ` header against `tokenType` (an `application/` prefix is ignored). Returns 401 on failure. `createVerifyRouter` throws if any of the three is missing.
3. If `validate` is `false`: decode the JWT without verification. Returns 401 if the token is malformed.
4. Parse `req.body.resource` with `resourceParser`; read `req.body.action` and `req.body.context`.
5. Include `x-request-id` header in `CollectorContext.headers` if present (collectors can forward it to upstream calls they make).
6. Run `attributePipeline.collect` and `rulePipeline.collect` in parallel; call `evaluate`.
7. Return `200 { decision: "allow" }` or `403 { decision: "deny", code, message }`.
8. Return `500 { decision: "deny", code: "internal_error" }` on unexpected errors.

### AppConfigSchema / AppConfig

```typescript
const AppConfigSchema = z.object({
  http: z.object({
    hostname: z.string().default("0.0.0.0"),
    port: z.coerce.number().default(3000),
    pathPrefix: z.string().default(""),
  }),
  oauth: z.object({
    jwt: z.object({
      secret: z.string(),
      validate: z.boolean().default(true),
      issuer: z.string().optional(),        // required when validate is true
      audience: z.union([z.string(), z.array(z.string())]).optional(), // required when validate is true
      tokenType: z.string().default("at+jwt"),
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
    maxBatchSize: z.coerce.number().int().positive().default(50),
  }),
});

type AppConfig = z.infer<typeof AppConfigSchema>;
```

Each entry in `attribute.collectors` and `rule.collectors` requires a `collector` field (the registered factory name). Additional fields are passed through to the factory as configuration.

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
        "rules": [{ "code": "invalid_scope", "message": "...", "passed": true }]
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

`reason.groups` lists every rule group in evaluation order — `passed`, plus every alternative for a failing group and the satisfying rule for a passing one. `code` / `message` come from the first failing group, as before.

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

Entries come back in request order, each the same object `POST /verify` would have answered for it. The status reports whether the batch was **decided**, not what it decided — a batch of denials is still `200`, and the caller reads each entry. `400 invalid_request` when `decisions` is absent, empty, over `verify.maxBatchSize`, or carries a malformed entry (the message names the index); `401` rejects the whole batch when the token does not verify.

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
