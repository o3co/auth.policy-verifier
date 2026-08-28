# @o3co/auth-policy-verifier-standalone

auth.policy-verifier のデプロイ可能なサーバーテンプレートです。このパッケージはコンポジションルートとして機能し、設定の読み込み・モジュールのロード・Express サーバーの起動を担います。`@o3co/create-auth-policy-verifier` によって生成されます。

## 使い方

```sh
pnpm install
OAUTH_JWT_SECRET=$(openssl rand -hex 32) \
  OAUTH_JWT_ISSUER=https://issuer.example.com \
  OAUTH_JWT_AUDIENCE=https://api.example.com \
  pnpm run start
```

`OAUTH_JWT_SECRET` はデコード後の長さで 32 バイト（256 ビット）以上を要求し、下回る値は起動時に拒否されます。[HS256 シークレットの強度](#hs256-シークレットの強度)を参照。

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
| `OAUTH_JWT_SECRET` | （必須） | HMAC-HS256 JWT 署名シークレット。デコード後 32 バイト以上 — [HS256 シークレットの強度](#hs256-シークレットの強度)を参照 |
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
| `LOG_LEVEL` | `info` | 出力する最低レベル: `trace`\|`debug`\|`info`\|`warn`\|`error`\|`fatal`\|`silent`。decision ログのスイッチも兼ねる — [可観測性](#可観測性)を参照 |

## HS256 シークレットの強度

`OAUTH_JWT_SECRET` は鍵素材として **32 バイト（256 ビット）以上**を持つ必要があります。足りない値は config パース時に拒否されるため、推測可能な鍵で稼働し続けるのではなく起動時に失敗します。

HS256 は対称鍵です。トークンを検証する値がそのままトークンを署名する値なので、推測された場合の被害は「発行済みトークンを読める」ことではなく「任意の subject のトークンを発行できる」ことです。RFC 7518 §3.2 はハッシュ出力幅以上の鍵を要求しており、auth.provider も同じ共有値に同じ下限を課しています。

```sh
OAUTH_JWT_SECRET=$(openssl rand -hex 32)      # 64 文字 / 32 バイト
OAUTH_JWT_SECRET=$(openssl rand -base64 32)   # 44 文字 / 32 バイト
```

判定は**デコード後**の素材に対して、もっとも小さく読める解釈で行います。攻撃者が実際に使えるのがその解釈だからです。

- `openssl rand -hex 16` は 32 *文字* だが 16 *バイト* しかない — 拒否。
- ランダムな英数字 32 文字は base64 本体として読めるため 24 バイト — 拒否。1 文字あたり 62 通りは約 5.95 ビットであり、8 ビットではない。
- 記号を含むパスフレーズは UTF-8 長で測られるため、32 文字なら通る。

同じ下限がローテーションブロックの `previousSecrets[].secret` 全件にも適用されます — 退役したシークレットも重複期間中は検証鍵であり、現行と同じようにトークンを発行できるからです。

この検査で見えるのは長さだけです。40 文字の英文は 40 バイトと数えられますが実際の強度ははるかに低いので、値は必ずランダムに生成してください。

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

`GET /metrics` も非ゲートです。理由と、ループバック以外に bind したときに何を意味するかは [`/metrics` への到達方法](#metrics-への到達方法)を参照してください。

## 可観測性

テンプレートは [pino](https://getpino.io) を使って stdout に NDJSON を出力し、`GET /metrics` で Prometheus メトリクスを提供します。どちらも既定で有効です。

### decision ログ

判定 1 件ごとに `decision` という名前の構造化イベントを `info` で 1 行出力します。

```json
{"level":30,"msg":"decision","requestId":"6f1c…","sub":"user-42","resource":"project:7","action":"read","decision":"deny","code":"invalid_scope","deniedBy":{"ruleType":"scope","refused":["invalid_scope"]},"durationMs":0.412}
```

| フィールド | 意味 |
|---|---|
| `sub` | 提示されたトークンの JWT `sub`。トークンが持たない場合は省略される |
| `resource` / `action` | 呼び出し元が送ったそのままの値 |
| `decision` | `allow` または `deny` |
| `code` | deny のみ — 呼び出し元がワイヤ上で受け取ったコードと同じ |
| `satisfiedBy` | allow のみ — 各グループを満たしたルールの `{ruleType, code}` |
| `deniedBy` | deny のみ — 最初に失敗したグループと、そこで拒否した全代替ルール |
| `requestId` | 呼び出し元が送った `x-request-id`。無い場合は省略される |
| `durationMs` | Collector パイプラインと evaluator に費やした時間。HTTP の往復時間ではない |

判定 1 件につき 1 行なので、N 件の `POST /verify/batch` は同一 `requestId` を持つ N 行を出力します。アラートとインデックスはイベント名に対して張り、メッセージ本文には張らないでください。

**スイッチは `LOG_LEVEL` です。** この行は `info` なので `warn` にすればストリームごと止まります。忘れるべき 2 つ目のフラグはありません。deny は decision point にとって障害ではなく *正常な* 結果なので、`warn` には送っていません。送ってしまえば任意の呼び出し元が warn レベルのノイズを製造でき、`warn` が「何かがおかしい」を意味しなくなります。アラートはメトリクスに、「なぜ」はログに求めてください。

**意図的に載せていないもの:**

- **生の bearer トークンと、`sub` を超えるクレーム集合。** トークンはメールアドレスやグループ所属など発行者が入れた任意の情報を運びますが、判定の説明にはどれも不要です。この記録は成功リクエストを含む全リクエストで書かれ、トークンとは影響範囲の異なるアグリゲータへ送られます。
- **呼び出し元の `context` オブジェクト。** 自由形式で collector にそのまま渡されるため、呼び出し側サービスのリクエストペイロードが行き着く場所そのものです。これを記録すると監査ストリームがそのペイロードの複製になります。
- **ルールの `message` 文字列。** 既に行に載っている resource と action から導かれる内容です。

### メトリクス

`GET /metrics` は Prometheus text exposition format を返します。

| メトリクス | 種別 | ラベル | 何に答えるか |
|---|---|---|---|
| `auth_decisions_total` | counter | `decision` | allow/deny 比率。系列はちょうど 2 本 |
| `auth_denials_total` | counter | `code` | どのルールが deny しているか — ログ行の `deniedBy` の集計版 |
| `auth_decision_duration_seconds` | histogram | `decision` | パイプラインと evaluator に費やした時間 |
| `http_request_duration_seconds` | histogram | `method`, `route`, `status` | リクエストレート・エラーレート・レイテンシ（RED メソッド） |
| `auth_policy_verifier_*` | 各種 | — | Node プロセス既定メトリクス — event loop lag, heap, GC, handles |

`http_request_duration_seconds` は [auth.provider](https://github.com/o3co/auth.provider) と同じ名前・同じラベル集合なので、1 つの Prometheus job と 1 つのダッシュボード規約でスタックの両側を賄えます。

deny はエラーではないので、書く価値のあるアラートは deny の存在ではなく `rate(auth_decisions_total{decision="deny"}[5m]) / rate(auth_decisions_total[5m])` の *変化* に対するものです。

#### すべてのラベルは有界

有界でないラベルは値ごとに新しい時系列を作り出します。これは、監視すべき対象を監視する仕組みそのものをメトリクスエンドポイントが落とす典型的な経路です。以下のいずれも `/metrics` へのアクセスなしに到達できます。

- **`resource` と `action` はそもそもラベルにしていません。** これらはリクエストボディから直接来るもので、構造上有界ではありません（`project:1`, `project:2`, …）。代わりに decision ログ行に載せています — 高カーディナリティの事実にはそちらが適切な媒体です。`sub` も同じ理由で除外しています（ユーザーごとに 1 系列になる）。
- **`route`** は URL ではなく Express の route *パターン*で、マッチしなかったもの（ポートに到達できる何かからの 404 プローブ）はすべて `route="unmatched"` に潰れます。
- **`method`** はこのサービスが実際に処理できる 9 メソッドの allowlist で、それ以外は `method="other"` です。Node のパーサは llhttp が知る全メソッド（`PURGE`, `MKCOL`, `PROPFIND` など）をサーバーに渡すため、`req.method` はパスと同程度に呼び出し元の制御下にあります。
- **`code`** は deployment が設定したルールに由来するので運用者が有界にできます — ただし `code` は `Rule` インターフェースのフィールドであり、ルールはリクエストごとに構築されるため、カスタム rule collector が resource から code を導出するようになるまでは 1 回の編集です。異なる値 32 個で打ち止め、それ以降は `code="other"` に潰れます。`code="other"` が伸びていること自体が、リクエストごとに code を作っているルールがあるというシグナルです。

#### `/metrics` への到達方法

`/metrics` は `HTTP_CALLER_AUTH_TOKEN` で**ゲートしていません**。Prometheus の scrape config が持つのは `authorization` / `basic_auth` / `oauth2` であって任意ヘッダではないため、`x-caller-token` でゲートすると標準の scraper からは scrape 不能になり、その回避策は *判定* を認可する資格情報を監視システムに渡すことになってしまいます。このエンドポイントが公開するのは有界ラベル上のカウントとレイテンシだけで、subject も resource も action も、個々の判定に関する情報も含みません。

**代わりに境界となるのは bind アドレスで、既定はループバックです。** したがって scraper は同一ホスト側に置く必要があります。

- **Kubernetes** — 同一 Pod のコンテナはネットワーク名前空間を共有するので、同じ Pod 内の Prometheus サイドカー（または OTel collector）が bind を変えずに `http://127.0.0.1:3000/metrics` を scrape できます。既定をそのまま保てるのはこの形です。
- **docker compose** — `docker-compose.yml` は既に `HTTP_HOSTNAME=0.0.0.0` を設定しています（コンテナ内のループバックはどこからも到達できないため）。この場合ポートは compose ネットワーク上の任意のコンテナから到達可能で、`/metrics` も同様です。publish する外向きインターフェースには出さず（`ports:` ではなく `expose:`）、scraper を同じネットワークに置いてください。
- **それ以外のループバック以外 bind** — `/verify` 自体と同様に、ネットワーク層（NetworkPolicy、セキュリティグループ、ファイアウォール）でポートを制限してください。

サイドカー構成の scrape config 例:

```yaml
scrape_configs:
  - job_name: auth-policy-verifier
    static_configs:
      - targets: ["127.0.0.1:3000"]
```

`HTTP_PATH_PREFIX` は他のエンドポイントと同様にこのパスも動かします。`HTTP_PATH_PREFIX=/pdp` なら `/pdp/metrics` になり、scrape config の `metrics_path` も合わせる必要があります。

**まだ公開していないもの:** 依存先ごとの `up` ゲージ（auth.provider はバックエンドストア向けに持っています）。ここでの相当物は JWKS エンドポイントですが、サンプリング対象になる readiness probe のレジストリがありません。依存先の一覧を別途手で持つゲージは、auth.provider が probe をサンプリングすることで避けた drift そのものです。そのレジストリができるまで、JWKS 障害は `jwt_verification_unavailable` ログイベントとして見えます — アラートを張れるようにこれは `error` で出力されています。

## デフォルトコレクター

以下のコレクターが `builtinCollectorsModule` を通じて登録されます。

**Attribute collectors**:

- `PayloadScopeCollector` — 検証済みサブジェクト属性（JWT のクレーム）から OAuth スコープを抽出する
- `PayloadSubjectIdCollector` — 検証済みサブジェクト属性（JWT のクレーム）からサブジェクト識別子を抽出する
- `RequestContextAttributeCollector` — リクエストボディの `context` の宣言済みフィールドを属性に昇格させる（既定では未接続。`attribute.collectors` に `attributes` マッピングを付けて追加する）

**Rule collectors**（認可ルールを解決）:

- `ResourceActionScopeRuleCollector` — トークンがスコープ `<action>:<resourceType>` を持つことを要求する
- `ResourceActionPermissionRuleCollector` — パーミッション `<resource.raw>.perm:<action>` を要求する（既定では未接続。下記参照）

### 出荷時のポリシー

`config/application.conf` はトークンの `scope` クレームだけで認可します。つまり、
リクエスト対象の resource と action に対して `<action>:<resourceType>` を bearer
トークンが持っているときにちょうど許可されます。スコープを発行する IdP があれば
認可ストアを別途立てなくてもそのまま機能し、かつ fail-closed です — スコープを
持たないトークンや誤ったスコープは拒否され、ルールが 1 つも集まらなかった
リクエストも拒否されます（`rule.onEmptyRuleSet = "deny"`）。

ルールは種類ごとにグループ化され、**すべてのグループが通る必要があります**。
そのため、属性を供給する attribute collector なしに rule collector を有効化すると、
何をもってしても満たせないグループができ、トークンの内容によらず全リクエストを
拒否する verifier になります。`ResourceActionPermissionRuleCollector` が
「未設定」ではなく明示的に無効なのはこのためです — このルールは permissions/roles
属性を読みますが、出荷時の `attribute.collectors` はそれを生成しません。有効化する
ときは供給側と同じ編集でセットにしてください（デプロイ単位の固定リストなら
`StaticPermissionCollector`、サブジェクトごとに異なるなら独自の `AttributeCollector`）。
`application.conf` の該当コレクターの隣に具体例があります。

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
  -e OAUTH_JWT_SECRET=$(openssl rand -hex 32) \
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
