# @o3co/auth-policy-verifier-standalone

auth.policy-verifier のデプロイ可能なサーバーテンプレートです。このパッケージはコンポジションルートとして機能し、設定の読み込み・モジュールのロード・Express サーバーの起動を担います。`@o3co/create-auth-policy-verifier` によって生成されます。

## 使い方

```sh
pnpm install
OAUTH_JWT_SECRET=your-secret pnpm run start
```

## 設定

設定は HOCON 形式で、次の順序で読み込まれます。

1. `config/application.conf` — ベース設定
2. `config/{ENV}.conf` — 現在の環境の overlay

`ENV = CONFIG_ENV || NODE_ENV || "development"` で決まります。overlay の値は
`application.conf` を上書きします。scaffold には `development.conf` と
`production.conf` が同梱されています。別の環境を追加する場合は
`config/staging.conf` のようにファイルを追加し、`CONFIG_ENV=staging` を設定してください。
`{ENV}.conf` が存在しない場合は起動時エラーになります。

個々の値は環境変数でも上書きできます。

| 変数 | デフォルト | 説明 |
|---|---|---|
| `HTTP_HOSTNAME` | `0.0.0.0` | バインドするホスト名 |
| `HTTP_PORT` | `3000` | バインドするポート番号 |
| `HTTP_PATH_PREFIX` | `""` | URL パスプレフィックス |
| `OAUTH_JWT_SECRET` | （必須） | HMAC-HS256 JWT 署名シークレット |
| `OAUTH_JWT_VALIDATE` | `true` | JWT 署名を検証するかどうか |

## デフォルトコレクター

以下のコレクターが `builtinCollectorsModule` を通じて登録されます。

**Attribute collectors**（JWT ペイロードから属性を抽出）:

- `PayloadScopeCollector` — OAuth スコープを抽出する
- `PayloadSubjectIdCollector` — サブジェクト識別子を抽出する

**Rule collectors**（認可ルールを解決）:

- `ResourceActionScopeRuleCollector` — リソース/アクションをスコープルールと照合する
- `ResourceActionPermissionRuleCollector` — リソース/アクションをパーミッションルールと照合する

使用されるリソースパーサーは `DotNotationResourceParser` です。

## カスタムモジュールの追加

`src/main.mts` を編集し、`createApp` に渡す `modules` 配列に独自モジュールを追加してください。

```ts
import { myModule } from "./my-module.mts";

const app = await createApp({
  pathResolver: import.meta.resolve,
  config,
  modules: [builtinCollectorsModule, builtinKeyResolversModule, myModule],
});
```

`builtinKeyResolversModule`（`@o3co/auth.policy-verifier.server` から import）は `HS256` / `RS256` / `ES256` / `EdDSA` の JWT 鍵解決に必須です。

## npm スクリプト

| スクリプト | コマンド | 説明 |
|---|---|---|
| `build` | `tsc` | TypeScript を `dist/` にコンパイルする |
| `start` | `node dist/main.mjs` | コンパイル済みサーバーを起動する |
| `debug` | `NODE_OPTIONS='--conditions=development' tsx watch src/main.mts` | ホットリロードで開発サーバーを起動する |
| `test` | `echo 'no tests configured'` | プレースホルダー（テスト未設定） |

## Docker

イメージをビルドしてコンテナを起動する:

```sh
make build
docker run -e OAUTH_JWT_SECRET=secret auth-policy-verifier
```

Docker Compose でローカル開発する場合:

```sh
make dev
```

## 関連

- [`@o3co/auth.policy-verifier.server`](../../packages/server) — Express アプリファクトリと設定スキーマ
- [`@o3co/auth.policy-verifier.builtins`](../../packages/builtins) — 組み込みコレクター実装
- [`@o3co/create-auth-policy-verifier`](../../create-app) — このテンプレートを生成する CLI スキャフォルダー
