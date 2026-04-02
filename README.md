# auth.policy-verifier

No-DSL ABAC policy engine. Runs as an HTTP service (`POST /verify`) or embeds as a library. Authorization logic is written in TypeScript via the Collector pattern, not a policy DSL.

- Replaceable with OPA or Cedar — `grpc.authz` supports all three as backends
- Runs as an HTTP sidecar — swapping to a different policy engine is a config change, not a code change

## Packages

| Package | npm | Description |
| --- | --- | --- |
| `packages/core` | `@o3co/auth.policy-verifier.core` | Types, `evaluate`, `AttributePipeline`, `RulePipeline` |
| `packages/foundation` | `@o3co/auth.policy-verifier.foundation` | Built-in collectors, rules, resource parser |
| `packages/express` | `@o3co/auth.policy-verifier.express` | Express HTTP server, `createApp`, `POST /verify` route |
| `templates/standalone` | — | Deployable server template |
| `create-app` | `create-o3co-policy-verifier` | CLI scaffolder |

## Quick Start

Use the standalone template to run the server:

```bash
npx create-o3co-policy-verifier my-policy-verifier
cd my-policy-verifier
pnpm install
OAUTH_JWT_SECRET=your-secret pnpm run start
```

Or run the template directly from this repo:

```bash
pnpm install
cd templates/standalone
OAUTH_JWT_SECRET=your-secret pnpm run start
```

```bash
curl -X POST http://localhost:3000/verify \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"resource": "project:1", "action": "read"}'
```

Response:

```json
{"decision": "allow"}
```

## How It Works

1. Extract JWT from Authorization header (verified via [jose](https://github.com/panva/jose))
2. **AttributeCollectors** gather subject attributes (scopes, permissions, roles) from JWT and external sources
3. **RuleCollectors** generate authorization rules based on resource + action
4. **Engine** evaluates: groups by ruleType, OR within group, AND across groups
5. Return allow/deny decision

## Configuration

HOCON config file with environment variable overrides. The `configPath` option is required when using `createApp`.

| Variable | Description | Default |
| --- | --- | --- |
| `OAUTH_JWT_SECRET` | JWT verification secret | (required) |
| `OAUTH_JWT_VALIDATE` | Validate JWT signature | `true` |
| `HTTP_PORT` | Server port | `3000` |
| `HTTP_HOSTNAME` | Server hostname | `0.0.0.0` |

Default collector config (`templates/standalone/config/application.conf`):

```hocon
attribute.collectors = [
  { collector = "PayloadScopeCollector" }
  { collector = "PayloadSubjectIdCollector" }
]

rule.collectors = [
  { collector = "ResourceActionScopeRuleCollector" }
  { collector = "ResourceActionPermissionRuleCollector" }
]
```

## Custom Collectors

Implement `AttributeCollector` or `RuleCollector` from `@o3co/auth.policy-verifier.core`, register at startup, and reference in config:

```typescript
// collectors/MyRoleCollector.mts
import type { Attributes, AttributeCollector, CollectorContext } from '@o3co/auth.policy-verifier.core'
import { ATTR_ROLES } from '@o3co/auth.policy-verifier.core'

export class MyRoleCollector implements AttributeCollector {
  constructor(private config: { endpointUrl: string }) {}

  async collect(context: CollectorContext): Promise<Attributes> {
    // fetch roles from your API
    return new Map([[ATTR_ROLES, roles]])
  }
}
```

```typescript
// main.mts
import { resolve } from 'node:path'
import { createApp } from '@o3co/auth.policy-verifier.express'
import { MyRoleCollector } from './collectors/MyRoleCollector.mjs'

const app = await createApp({
  configPath: resolve(import.meta.dirname, '../config/application.conf'),
  collectors: { MyRoleCollector },
})
app.listen(3000)
```

```hocon
attribute.collectors = [
  { collector = "PayloadScopeCollector" }
  { collector = "MyRoleCollector", endpointUrl = "https://api.example.com/roles" }
]
```

## Built-in Collectors

| Collector | Type | Description |
| --- | --- | --- |
| `PayloadScopeCollector` | Attribute | Extracts scopes from JWT |
| `PayloadSubjectIdCollector` | Attribute | Extracts userId/clientId from JWT |
| `StaticPermissionCollector` | Attribute | Returns hardcoded permissions from config |
| `StaticRoleCollector` | Attribute | Returns hardcoded roles from config |
| `ResourceActionScopeRuleCollector` | Rule | Creates scope rule: `{action}:{resourceType}` |
| `ResourceActionPermissionRuleCollector` | Rule | Creates permission rule: `{resource}.perm:{action}` |

## Library Usage

```typescript
import { AttributePipeline, RulePipeline, evaluate } from '@o3co/auth.policy-verifier.core'
import { PayloadScopeCollector, ResourceActionScopeRuleCollector, DotNotationResourceParser } from '@o3co/auth.policy-verifier.foundation'

const parser = new DotNotationResourceParser()
const resource = parser.parse('project:1')
const context = { payload: decodedJwt, resource, action: 'read' }

const attrs = await new AttributePipeline([new PayloadScopeCollector()]).collect(context)
const rules = await new RulePipeline([new ResourceActionScopeRuleCollector()]).collect(context)
const decision = evaluate(attrs, rules)
```

## Docker

```bash
make docker
docker run -e OAUTH_JWT_SECRET=secret auth-policy-verifier
```

## Development

```bash
pnpm install
pnpm -r build    # build all packages
pnpm -r test     # test all packages
```

## Related Projects

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 token issuance
- [auth.proxy](https://github.com/o3co/auth.proxy) — Token validation reverse proxy
- [auth](https://github.com/o3co/auth) — Architecture docs and E2E tests
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC authorization middleware

## License

Apache License 2.0 — Copyright 2026 1o1 Co. Ltd.
