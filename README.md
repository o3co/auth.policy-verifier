# auth.policy-verifier

No-DSL ABAC policy engine. Runs as an HTTP service (`POST /verify`) or embeds as a library. Authorization logic is written in TypeScript via the Collector pattern, not a policy DSL.

- Replaceable with OPA or Cedar — `grpc.authz` supports all three as backends
- Runs as an HTTP sidecar — swapping to a different policy engine is a config change, not a code change

## Quick Start

```bash
pnpm install
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

1. Extract JWT from Authorization header
2. **AttributeCollectors** gather subject attributes (scopes, permissions, roles) from JWT and external sources
3. **RuleCollectors** generate authorization rules based on resource + action
4. **Engine** evaluates: groups by ruleType, OR within group, AND across groups
5. Return allow/deny decision

## Custom Collectors

Write a class that implements `AttributeCollector` or `RuleCollector`, register it at startup, reference it in HOCON config:

```typescript
// collectors/MyRoleCollector.mts
import type { Attributes, AttributeCollector, CollectorContext } from '@o3co/auth.policy-verifier'
import { ATTR_ROLES } from '@o3co/auth.policy-verifier'

export class MyRoleCollector implements AttributeCollector {
  constructor(private config: { endpointUrl: string }) {}

  async collect(context: CollectorContext): Promise<Attributes> {
    // fetch roles from your API
    return new Map([[ATTR_ROLES, roles]])
  }
}
```

```typescript
// server.mts
import { createApp } from '@o3co/auth.policy-verifier/server'
import { MyRoleCollector } from './collectors/MyRoleCollector.mjs'

const app = await createApp({
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
| PayloadScopeCollector | Attribute | Extracts scopes from JWT |
| PayloadSubjectIdCollector | Attribute | Extracts userId/clientId from JWT |
| StaticPermissionCollector | Attribute | Returns hardcoded permissions from config |
| StaticRoleCollector | Attribute | Returns hardcoded roles from config |
| ResourceActionScopeRuleCollector | Rule | Creates scope rule: `{action}:{resourceType}` |
| ResourceActionPermissionRuleCollector | Rule | Creates permission rule: `{resource}.perm:{action}` |

## Configuration

HOCON config with environment variable overrides:

| Variable | Description | Default |
| --- | --- | --- |
| `OAUTH_JWT_SECRET` | JWT verification secret | (required) |
| `OAUTH_JWT_VALIDATE` | Validate JWT signature | `true` |
| `HTTP_PORT` | Server port | `3000` |
| `HTTP_HOSTNAME` | Server hostname | `0.0.0.0` |

## Docker

```bash
make docker
docker run -e OAUTH_JWT_SECRET=secret auth-policy-verifier
```

## Library Usage

```typescript
import { AttributePipeline, RulePipeline, evaluate } from '@o3co/auth.policy-verifier'
import { PayloadScopeCollector } from '@o3co/auth.policy-verifier'
import { ResourceActionScopeRuleCollector } from '@o3co/auth.policy-verifier'
import { DotNotationResourceParser } from '@o3co/auth.policy-verifier'

const parser = new DotNotationResourceParser()
const resource = parser.parse('project:1')
const context = { payload: decodedJwt, resource, action: 'read' }

const attrs = await new AttributePipeline([new PayloadScopeCollector()]).collect(context)
const rules = await new RulePipeline([new ResourceActionScopeRuleCollector()]).collect(context)
const decision = evaluate(attrs, rules)
```

## Related Projects

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 token issuance
- [auth.proxy](https://github.com/o3co/auth.proxy) — Token validation reverse proxy
- [auth](https://github.com/o3co/auth) — Architecture docs and E2E tests
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC authorization middleware

## License

Apache License 2.0
