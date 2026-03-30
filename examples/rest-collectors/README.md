# REST Collector Examples

These are reference implementations showing how to build custom Collectors that fetch attributes from external REST APIs.

## Usage

1. Copy the collector you need into your project
2. Modify the API URL and response parsing to match your service
3. Register it when creating the app:

```typescript
import { createApp } from '@o3co/auth.policy-verifier/server'
import { SampleRestRoleCollector } from './collectors/SampleRestRoleCollector.mjs'

const app = await createApp({
  collectors: { SampleRestRoleCollector },
})
```

4. Reference it in your HOCON config:

```hocon
attribute.collectors = [
  { collector = "PayloadScopeCollector" }
  { collector = "SampleRestRoleCollector", endpointUrl = "https://api.example.com/roles" }
]
```
