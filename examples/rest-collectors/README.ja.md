# REST Collector サンプル

外部 REST API から属性を取得するカスタム Collector のリファレンス実装。

## 使い方

1. 必要な Collector をプロジェクトにコピー
2. API URL とレスポンスのパースを自分のサービスに合わせて修正
3. アプリ作成時に登録:

```typescript
import { createApp } from '@o3co/auth.policy-verifier/server'
import { SampleRestRoleCollector } from './collectors/SampleRestRoleCollector.mjs'

const app = await createApp({
  collectors: { SampleRestRoleCollector },
})
```

4. HOCON 設定で参照:

```hocon
attribute.collectors = [
  { collector = "PayloadScopeCollector" }
  { collector = "SampleRestRoleCollector", endpointUrl = "https://api.example.com/roles" }
]
```
