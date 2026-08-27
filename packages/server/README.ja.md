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
  jwt: VerifyRouterJwtConfig;
  resourceParser: ResourceParser;
  attributePipeline: AttributePipeline;
  rulePipeline: RulePipeline;
  /** 評価セマンティクスの上書き。省略時は空 rule set を deny。 */
  evaluateOptions?: EvaluateOptions;
  /** POST /verify/batch の 1 リクエストあたり件数上限。既定は 50。 */
  maxBatchSize?: number;
}

// `validate` による判別可能ユニオン。検証パラメータは検証するときにだけ存在する。
type VerifyRouterJwtConfig =
  | {
      validate: true;
      key: unknown;             // KeyResolverFactory が返す鍵
      algorithms: string[];
      issuer: string | string[];    // RFC 9068 §4 iss
      audience: string | string[];  // RFC 9068 §4 aud
      tokenType: string;            // 受け入れる typ ヘッダ（例: "at+jwt"）
    }
  | { validate: false };

function createVerifyRouter(config: VerifyRouterConfig): express.Router
```

`POST /verify` を処理する Express Router を返します。`createApp` が内部で呼び出すため、通常は直接使用する必要はありません。ルーターを独立してマウントしたい場合のみ直接利用してください。

リクエスト処理フロー:

1. `Authorization: <type> <token>` ヘッダーを取得する。存在しない場合は 401 を返す。
2. `validate` が `true` の場合: 署名に加えて RFC 9068 §4 のクレームを検証する — `iss` を `issuer` と、`aud` を `audience` と、`typ` ヘッダを `tokenType` と照合する（`application/` プレフィックスは無視）。失敗時は 401 を返す。3 つのいずれかが欠けている場合、`createVerifyRouter` は例外を投げる。
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
      issuer: z.union([z.string(), z.array(z.string())]).optional(),   // validate = true のとき必須
      audience: z.union([z.string(), z.array(z.string())]).optional(), // validate = true のとき必須
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

`subject` はボディでは受け付けません。検証済みトークンの `sub` クレームから取ります — ここで受け付けると、
トークンを持つ誰もが他人についての決定を要求できてしまうためです。

**レスポンス — 許可**

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

**レスポンス — 拒否**

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

`reason.groups` は評価順に全ルールグループを列挙します — `passed` と、そのグループで実際に走ったルールを
評価順に並べた `evaluated` が入ります。失敗グループは全代替ルールを走らせて（列挙して）います。
通過グループは最初に通ったルールで打ち切るため、`evaluated` は先に試して失敗した代替ルールに続けて
そのルールで終わり、決め手となったルールは `satisfiedBy`（通過グループにのみ存在し、失敗グループには
付きません）として明示されます。
`code` / `message` は従来どおり最初に失敗したグループから取ります。

**レスポンス — 予期しないエラー**

```http
HTTP/1.1 500 Internal Server Error

{ "decision": "deny", "code": "internal_error" }
```

### POST /verify/batch

同じ decision 契約で、1 往復に N 件 — N 個のリソースの絞り込みが N 回ではなく 1 回のリクエストで済みます。

**リクエスト**

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

1 つのトークンがバッチ全体を認可し、各エントリが自分の `resource` / `action` / `context` を持ちます。

**レスポンス**

```http
HTTP/1.1 200 OK

{ "decisions": [ { ... }, { ... } ] }
```

エントリはリクエスト順で返り、それぞれ `POST /verify` が同じ入力に返すのと同じオブジェクトです。
ステータスはバッチが**判定できたか**を表し、判定結果そのものではありません — 全件 deny でも `200` で、
呼び出し側が各エントリを読みます。`decisions` が無い / 空 / `verify.maxBatchSize` 超過 / 不正なエントリを
含む場合は `400 invalid_request`（メッセージが該当 index を示します）、トークンが検証できない場合は
`401` でバッチ全体を拒否します。

## 使い方

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
  modules: [builtinCollectorsModule, builtinKeyResolversModule, customModule],
})
```

`builtinKeyResolversModule` は HS256 / RS256 / ES256 / EdDSA のファクトリーを `keyResolverRegistry` に登録します。カスタムモジュールと並べて合成してください。独自の鍵解決モジュールを提供する場合のみ省略可能です。

## 関連

- [`@o3co/auth.policy-verifier.core`](../core/README.ja.md) — 型定義、`evaluate`、`AttributePipeline`、`RulePipeline`、Module インフラ
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.ja.md) — 組み込みコレクターとパーサー
- [auth.policy-verifier ルート README](../../README.ja.md) — アーキテクチャ概要・設定リファレンス・Docker
