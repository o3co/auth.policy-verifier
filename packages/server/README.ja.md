# @o3co/auth.policy-verifier.server

auth.policy-verifier 向けの Express HTTP サーバーです。モジュールと設定からアプリケーションを組み立てる `createApp` と、認可判定を行う `POST /verify` を提供します。

## インストール

```bash
npm install @o3co/auth.policy-verifier.server
```

## パブリック API

### createApp

```typescript
interface CreateAppOptions {
  pathResolver: PathResolver;
  config: AppConfig;
  modules: Module[];
}

function createApp(options: CreateAppOptions): Promise<express.Express>
```

設定済みの Express アプリケーションを組み立てて返します。リスニングは開始しません — 別途 `app.listen(...)` を呼び出してください。

実行ステップ:

1. AttributeCollector・RuleCollector・ResourceParser のファクトリ用 `Registry` インスタンスを生成する。
2. `modules` の各モジュールに対して `mod.init(context)` を順に呼び出し、各モジュールがファクトリ関数を登録できるようにする。
3. `config.attribute.collectors` と `config.rule.collectors` の各エントリについて、`collector` 名で登録済みファクトリを検索して AttributeCollector と RuleCollector を生成する。
4. `config.resource.parser` から ResourceParser を生成する。
5. `config.http.pathPrefix` 以下に `GET /healthcheck` と `POST /verify` をマウントする。
6. 設定済みの `express.Express` インスタンスを返す。

`pathResolver` には、コンポジションルート側の `import.meta.resolve`（または互換リゾルバー）を渡します。モジュール相対パスの解決が必要なモジュールに渡されます。

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

`POST /verify` を処理する Express Router を返します。`createApp` が内部で呼び出すため、通常は直接使用する必要はありません。ルーターを独立してマウントしたい場合のみ直接利用してください。

リクエスト処理フロー:

1. `Authorization: <type> <token>` ヘッダーを取得する。存在しない場合は 401 を返す。
2. `validate` が `true` の場合: HS256 で JWT を検証する。失敗時は 401 を返す。
3. `validate` が `false` の場合: JWT を検証なしでデコードする。不正なトークンの場合は 401 を返す。
4. `req.body.resource` を `resourceParser` でパースし、`req.body.action` と `req.body.context` を読み取る。
5. `x-request-id` ヘッダーが存在する場合、`CollectorContext.headers` に含める（コレクターが上流呼び出し時に転送可能）。
6. `attributePipeline.collect` と `rulePipeline.collect` を並列実行し、`evaluate` を呼び出す。
7. `200 { decision: "allow" }` または `403 { decision: "deny", code, message }` を返す。
8. 予期しないエラーが発生した場合は `500 { decision: "deny", code: "internal_error" }` を返す。

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

`attribute.collectors` と `rule.collectors` の各エントリには `collector` フィールド（登録済みファクトリ名）が必須です。追加フィールドはファクトリへの設定としてそのまま渡されます。

### POST /verify

**リクエスト**

```http
POST /verify HTTP/1.1
Authorization: Bearer <jwt>
Content-Type: application/json
x-request-id: <省略可>

{
  "resource": "project:1",
  "action": "read",
  "context": {}
}
```

**レスポンス — 許可**

```http
HTTP/1.1 200 OK

{ "decision": "allow" }
```

**レスポンス — 拒否**

```http
HTTP/1.1 403 Forbidden

{ "decision": "deny", "code": "<code>", "message": "<message>" }
```

**レスポンス — 予期しないエラー**

```http
HTTP/1.1 500 Internal Server Error

{ "decision": "deny", "code": "internal_error" }
```

## 使い方

```typescript
import { resolve } from 'node:path'
import { parseFile } from '@o3co/ts.hocon'
import { validate } from '@o3co/ts.hocon/zod'
import { createApp, AppConfigSchema } from '@o3co/auth.policy-verifier.server'
import { builtinCollectorsModule } from '@o3co/auth.policy-verifier.builtins'

const config = validate(
  parseFile(resolve(import.meta.dirname, '../config/application.conf')),
  AppConfigSchema,
)

const app = await createApp({
  pathResolver: import.meta.resolve,
  config,
  modules: [builtinCollectorsModule],
})

app.listen(config.http.port, config.http.hostname, () => {
  console.log(`${config.http.hostname}:${config.http.port} でリスニング中`)
})
```

カスタムモジュールを追加するには、`@o3co/auth.policy-verifier.core` の `Module` を実装して `modules` 配列に渡します。

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
  modules: [builtinCollectorsModule, customModule],
})
```

## 関連

- [`@o3co/auth.policy-verifier.core`](../core/README.ja.md) — 型定義、`evaluate`、`AttributePipeline`、`RulePipeline`、Module インフラ
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.ja.md) — 組み込みコレクターとパーサー
- [auth.policy-verifier ルート README](../../README.ja.md) — アーキテクチャ概要・設定リファレンス・Docker
