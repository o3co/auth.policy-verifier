# auth.policy-verifier

DSL 不要の ABAC ポリシーエンジン。HTTP サービス（`POST /verify`）として動作、またはライブラリとして組み込み可能。認可ロジックはポリシー DSL ではなく TypeScript の Collector パターンで記述。

- OPA や Cedar に置き換え可能 — `grpc.authz` は3つすべてをバックエンドとしてサポート
- HTTP サイドカーとして動作 — 別のポリシーエンジンへの差し替えはコード変更ではなく設定変更で完了

## クイックスタート

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

レスポンス:

```json
{"decision": "allow"}
```

## 仕組み

1. Authorization ヘッダーから JWT を抽出
2. **AttributeCollector** がサブジェクト属性（スコープ、パーミッション、ロール）を JWT や外部ソースから収集
3. **RuleCollector** がリソース + アクションに基づいて認可ルールを生成
4. **Engine** が評価: ruleType でグループ化、グループ内は OR、グループ間は AND
5. allow/deny の判定を返す

## カスタム Collector

`AttributeCollector` または `RuleCollector` を実装するクラスを書き、起動時に登録して、HOCON 設定で参照する:

```typescript
// collectors/MyRoleCollector.mts
import type { Attributes, AttributeCollector, CollectorContext } from '@o3co/auth.policy-verifier'
import { ATTR_ROLES } from '@o3co/auth.policy-verifier'

export class MyRoleCollector implements AttributeCollector {
  constructor(private config: { endpointUrl: string }) {}

  async collect(context: CollectorContext): Promise<Attributes> {
    // 自前の API からロールを取得
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

## 組み込み Collector

| Collector | タイプ | 説明 |
| --- | --- | --- |
| PayloadScopeCollector | Attribute | JWT からスコープを抽出 |
| PayloadSubjectIdCollector | Attribute | JWT から userId/clientId を抽出 |
| StaticPermissionCollector | Attribute | 設定からハードコードされたパーミッションを返す |
| StaticRoleCollector | Attribute | 設定からハードコードされたロールを返す |
| ResourceActionScopeRuleCollector | Rule | スコープルールを作成: `{action}:{resourceType}` |
| ResourceActionPermissionRuleCollector | Rule | パーミッションルールを作成: `{resource}.perm:{action}` |

## 設定

HOCON 設定（環境変数でオーバーライド可能）:

| 変数 | 説明 | デフォルト |
| --- | --- | --- |
| `OAUTH_JWT_SECRET` | JWT 検証シークレット | (必須) |
| `OAUTH_JWT_VALIDATE` | JWT 署名を検証する | `true` |
| `HTTP_PORT` | サーバーポート | `3000` |
| `HTTP_HOSTNAME` | サーバーホスト名 | `0.0.0.0` |

## Docker

```bash
make docker
docker run -e OAUTH_JWT_SECRET=secret auth-policy-verifier
```

## ライブラリとしての利用

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

## 関連プロジェクト

- [auth.provider](https://github.com/o3co/auth.provider) — OAuth 2.0 トークン発行
- [auth.proxy](https://github.com/o3co/auth.proxy) — トークン検証リバースプロキシ
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントと E2E テスト
- [grpc.authz](https://github.com/o3co/grpc.authz) — gRPC 認可ミドルウェア

## ライセンス

Apache License 2.0
