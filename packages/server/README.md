# @o3co/auth.policy-verifier.server

Express HTTP server for auth.policy-verifier. Provides `createApp` to assemble the application from modules and config, and `POST /verify` for authorization decisions.

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
5. Mounts `GET /healthcheck` and `POST /verify` under `config.http.pathPrefix`.
6. Returns the configured `express.Express` instance.

`pathResolver` must be `import.meta.resolve` (or a compatible resolver) from the composition root. It is passed to modules that need to resolve module-relative paths.

### createVerifyRouter

```typescript
interface VerifyRouterConfig {
  jwt: { secret: string; validate: boolean };
  resourceParser: ResourceParser;
  attributePipeline: AttributePipeline;
  rulePipeline: RulePipeline;
}

function createVerifyRouter(config: VerifyRouterConfig): express.Router
```

Returns an Express Router that handles `POST /verify`. `createApp` calls this internally; use it directly only if you need to mount the router independently.

Request flow:

1. Extract `Authorization: <type> <token>` header. Returns 401 if missing.
2. If `validate` is `true`: verify the JWT with HS256 using `secret`. Returns 401 on failure.
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

**Response — allow**

```http
HTTP/1.1 200 OK

{ "decision": "allow" }
```

**Response — deny**

```http
HTTP/1.1 403 Forbidden

{ "decision": "deny", "code": "<code>", "message": "<message>" }
```

**Response — unexpected error**

```http
HTTP/1.1 500 Internal Server Error

{ "decision": "deny", "code": "internal_error" }
```

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
