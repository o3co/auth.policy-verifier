# @o3co/auth-policy-verifier-standalone

auth.policy-verifier のデプロイ可能なサーバーテンプレートです。このパッケージはコンポジションルートとして機能し、設定の読み込み・モジュールのロード・Express サーバーの起動を担います。`create-o3co-policy-verifier` によって生成されます。

## 使い方

```sh
pnpm install
OAUTH_JWT_SECRET=your-secret pnpm run start
```

## 設定

設定は `config/application.conf`（HOCON 形式）から読み込まれます。個々の値は環境変数で上書きできます。

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
  modules: [builtinCollectorsModule, myModule],
});
```

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
- [`create-o3co-policy-verifier`](../../create-app) — このテンプレートを生成する CLI スキャフォルダー
