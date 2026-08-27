# @o3co/auth-policy-verifier-standalone

auth.policy-verifier のデプロイ可能なサーバーテンプレートです。このパッケージはコンポジションルートとして機能し、設定の読み込み・モジュールのロード・Express サーバーの起動を担います。`@o3co/create-auth-policy-verifier` によって生成されます。

## 使い方

```sh
pnpm install
OAUTH_JWT_SECRET=your-secret \
  OAUTH_JWT_ISSUER=https://issuer.example.com \
  OAUTH_JWT_AUDIENCE=https://api.example.com \
  pnpm run start
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
| `HTTP_HOSTNAME` | `127.0.0.1` | バインドするホスト名。既定はループバック — [信頼境界](#信頼境界)を参照。コンテナでは `0.0.0.0` の指定が必要 |
| `HTTP_PORT` | `3000` | バインドするポート番号 |
| `HTTP_PATH_PREFIX` | `""` | URL パスプレフィックス |
| `HTTP_CALLER_AUTH_TOKEN` | （未設定） | 呼び出し元サービスが提示する共有資格情報。未設定の場合、ポートに到達できる任意の相手が判定を要求できる |
| `HTTP_CALLER_AUTH_HEADER` | `x-caller-token` | その資格情報を載せるヘッダ |
| `OAUTH_JWT_SECRET` | （必須） | HMAC-HS256 JWT 署名シークレット |
| `OAUTH_JWT_ISSUER` | （必須） | この deployment が受け入れる issuer — RFC 9068 §4 `iss` |
| `OAUTH_JWT_AUDIENCE` | （必須） | この resource server を指す audience — RFC 9068 §4 `aud` |
| `OAUTH_JWT_JWKS_URI` | — | RS256/ES256/EdDSA の JWKS エンドポイント。`https://` 必須。平文 `http://` はループバックホスト（`localhost`, `127.0.0.0/8`, `[::1]`）のみ許可 |
| `OAUTH_JWT_JWKS_TIMEOUT_MS` | `5000` | JWKS 取得をこの時間で打ち切る |
| `OAUTH_JWT_JWKS_COOLDOWN_MS` | `30000` | JWKS 再取得の最小間隔 |
| `OAUTH_JWT_JWKS_CACHE_MAX_AGE_MS` | `600000` | 取得した JWKS をキャッシュから返す期間 |
| `OAUTH_JWT_TOKEN_TYPE` | `at+jwt` | 受け入れる `typ` ヘッダ。同じ鍵で署名された id/refresh/logout token を拒否する |
| `OAUTH_JWT_MODE` | `verify` | `verify` はトークンを完全検証。明示的な `insecure-decode`（テスト専用）は署名検証なしでデコードする — `exp`/`nbf` は引き続き強制される |
| `RULE_ON_EMPTY_RULE_SET` | `deny` | ルールが 1 つも集まらなかったときの決定（`deny` \| `allow`） |
| `VERIFY_MAX_BATCH_SIZE` | `50` | `POST /verify/batch` の件数上限 |

## 信頼境界

`/verify` は認可の判定結果を返すため、誰でも到達できるポートは decision oracle になります。subject トークンが示すのは判定の *対象* であって、`resource` / `action` / `context` を渡したのがどのサービスかではありません。

そのためテンプレートの既定 bind は **ループバック** です。これはサイドカー構成 — enforcement 層が同一ホストで動き、それ以外は接続できません。

別ホスト・別コンテナから到達させるのは明示的なオプトインで、次の 2 つが必要です。

```sh
HTTP_HOSTNAME=0.0.0.0             # そもそもポートに到達できるようにする
HTTP_CALLER_AUTH_TOKEN=<secret>   # そのうえで自分の enforcement 層にだけ応答させる
```

`docker-compose.yml` は既に `HTTP_HOSTNAME=0.0.0.0` を設定しています。コンテナ内でのループバックは「どこからも到達できない」ことを意味し、publish したポートが繋がらないためです。資格情報は `.env` に置いてください。

`HTTP_CALLER_AUTH_TOKEN` を設定すると、`/verify` と `/verify/batch` への全リクエストが `HTTP_CALLER_AUTH_HEADER`（既定 `x-caller-token`。subject トークンを載せる `Authorization` を避けているのは意図的）にその値をそのまま載せる必要があります。

```http
POST /verify HTTP/1.1
x-caller-token: <secret>
Authorization: Bearer <jwt>
```

それ以外は body のパースより前に `401 { "decision": "deny", "code": "caller_unauthenticated", "message": "Caller authentication failed" }` を返します。`GET /healthcheck` は常に非ゲートなので、コンテナの healthcheck はそのまま動作します。

資格情報を未設定のままにする運用もサポートされており、ループバックであれば問題ありません。ループバック以外に bind した場合は起動時に `unauthenticated_non_loopback_bind` が warn で記録されます — 修正する価値があるのはこの組み合わせです。

## デフォルトコレクター

以下のコレクターが `builtinCollectorsModule` を通じて登録されます。

**Attribute collectors**:

- `PayloadScopeCollector` — JWT ペイロードから OAuth スコープを抽出する
- `PayloadSubjectIdCollector` — JWT ペイロードからサブジェクト識別子を抽出する
- `RequestContextAttributeCollector` — リクエストボディの `context` の宣言済みフィールドを属性に昇格させる（既定では未接続。`attribute.collectors` に `attributes` マッピングを付けて追加する）

**Rule collectors**（認可ルールを解決）:

- `ResourceActionScopeRuleCollector` — リソース/アクションをスコープルールと照合する
- `ResourceActionPermissionRuleCollector` — リソース/アクションをパーミッションルールと照合する

使用されるリソースパーサーは `DotNotationResourceParser` です。`segment *( "." segment )`
（`segment = type [ ":" id ]`）を受け付け、セグメントの type を `.` で結合して `resourceType` を導出します
— つまり `"project:1.member:2"` は type `project.member`、id `2` です。この文法から外れたリソース文字列
（`a..b` のような空セグメント、`a:1:2` のような 2 つ目の `:`、前後の空白）は `400 invalid_request` になります。
`resourceType` は scope ルールが認可する対象そのものなので、修復せず拒否します。

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
docker run \
  -p 3000:3000 \
  -e HTTP_HOSTNAME=0.0.0.0 \
  -e HTTP_CALLER_AUTH_TOKEN=<secret> \
  -e OAUTH_JWT_SECRET=secret \
  -e OAUTH_JWT_ISSUER=https://issuer.example.com \
  -e OAUTH_JWT_AUDIENCE=https://api.example.com \
  auth-policy-verifier
```

最初の 2 つは [信頼境界](#信頼境界) で述べた opt-in の組で、ポートを公開する
こと自体が両方を必要にします:

- `HTTP_HOSTNAME=0.0.0.0` — 設定は既定で loopback に bind しますが、コンテナ内
  での loopback は「どこからも到達できない」を意味し、公開したポートは決して
  繋がらないため。
- `HTTP_CALLER_AUTH_TOKEN` — 同じ設定によって `/verify` がポートに到達できる
  すべてのものから届く状態になり、`/verify` は認可判断を返すため。省略して
  よいのは、ホストの外から公開ポートに到達できない場合だけです。

Docker Compose でローカル開発する場合:

```sh
make dev
```

`docker-compose.yml` は `HTTP_HOSTNAME=0.0.0.0` を自身で設定し、任意の `.env`
を読み込みます。資格情報は供給**しません** — `HTTP_CALLER_AUTH_TOKEN` はその
`.env` に置いてください。

### `pnpm-lock.yaml` はビルド入力

同じソースからの 2 回のビルドが 2 つの異なるイメージを生まないようにするのが
`pnpm install --frozen-lockfile` です。そのため `Dockerfile` は
`pnpm-lock.yaml` を COPY し、無ければビルドは失敗します。
`create-auth-policy-verifier` が scaffold 時に生成するので、コミットして
ください。無い場合（オフラインでの scaffold、または `--no-lockfile`）は
`pnpm install` を一度実行してその結果をコミットします。

したがって依存更新は lockfile の変更です: `pnpm update` → commit → 再ビルド。
ベースイメージを digest で固定しているのも同じ理由で、更新方法も同じ —
tag と digest を意図的に一緒に上げます。

### HEALTHCHECK が報告するもの

コンテナの healthcheck は `127.0.0.1` ではなく、**コンテナ自身の到達可能
アドレス**を probe します。これは意図的です。loopback に対する probe は、
サーバーが loopback に bind していて誰も到達できない状態でも成功してしまい —
外から見れば死んでいるコンテナを「healthy」と報告します。実際に到達可能な
アドレスを叩けば呼び出し元と同じ問いになるため、`HTTP_HOSTNAME=0.0.0.0` の
付け忘れは隠れずに `unhealthy` として現れます。

`GET /healthcheck` は `http.callerAuth` で決してゲートされないので、probe に
資格情報は不要です。`HTTP_PATH_PREFIX` と `HTTP_PORT` には追従します。

例外は 1 つ、呼び出し元と network namespace を共有する sidecar 構成です。
そこでは loopback bind が正しく、到達可能アドレスでは何も listen していま
せん。そのサービスでは `healthcheck:` を override してください。

## 関連

- [`@o3co/auth.policy-verifier.server`](../../packages/server) — Express アプリファクトリと設定スキーマ
- [`@o3co/auth.policy-verifier.builtins`](../../packages/builtins) — 組み込みコレクター実装
- [`@o3co/create-auth-policy-verifier`](../../create-app) — このテンプレートを生成する CLI スキャフォルダー
