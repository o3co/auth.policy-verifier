# @o3co/auth.policy-verifier.server

最終更新: 2026-09-23

auth.policy-verifier 向けの Express HTTP サーバーです。モジュールと設定からアプリケーションを組み立てる `createApp` と、認可判定を行う `POST /verify` / `POST /verify/batch` を提供します。

## 責務と役割

**役割。** [`@o3co/auth.policy-verifier.core`](../core/README.ja.md) の pipeline と評価器を HTTP の判定エンドポイントにする、Node 専用のホストです。コンポジションルート — [standalone テンプレート](../../templates/standalone/README.ja.md)、または [`create-app`](../../create-app/README.ja.md) で生成したプロジェクト — が設定とモジュールを渡して `createApp` を呼びます。このパッケージが依存するワークスペースパッケージは core だけです（[`@o3co/auth.policy-verifier.builtins`](../builtins/README.ja.md) の組み込み collector は import せず、モジュールとして渡されます）。

**持つもの:** HTTP の面（`/verify`、`/verify/batch`、liveness probe、`/metrics`）とそのステータスコード・deny エンベロープ。subject の認証（組み込みの bearer-JWT authenticator、key resolver、モジュールが別の authenticator を供給するための registry）。呼び出し元サービスの認証（`http.callerAuth`）。アプリケーション設定スキーマと、両方の設定境界がすべての knob を同じ方法で読むというルール。1 つの判定の実行とその報告（`decision` 行、失敗カテゴリ、Prometheus カウンタ）。

**持たないもの:** 評価のセマンティクスと `Rule` / collector / `Module` の契約（core）。具体的な collector・rule・resource parser（builtins、cedar、またはデプロイ自身のモジュール）。プロセスのライフサイクル — 設定ファイルの読み込み、`app.listen`、シグナル処理 — はコンポジションルートに残ります。

**別パッケージである理由:** core は実行時依存を持たず edge ランタイムでも動きます。このパッケージは Node 専用で、`express`、`jose`、`prom-client`、`zod` を持ち込みます。これらをここに閉じ込めることで、評価だけを行う利用者（edge function、テスト）はどれも持ち込まずに core を使えます。

パッケージ内部のソースの分け方: [`src/README.md`](src/README.md)。

## Bearer 認証の境界

組み込みの authenticator が受け付けるのは、`Bearer` スキームで提示された、何にも束縛されていないアクセストークンです。
それ以上にどのトークンを受け付けるかは `tokenType` が pin します（`"*"` は何も pin せず、テスト専用のデコードモードは署名を検証しません）。
`cnf` クレームを持つトークンは、その中身が何であれ `401 invalid_token` で拒否します — DPoP、mTLS、
不正な形の confirmation、未知の方式のいずれもです。これは `/verify` と `/verify/batch` の両方に適用され、
テスト専用のデコードモードも例外ではありません。リクエストの context で「所持は検証済み」と主張することは
できません。束縛トークンを使うデプロイには、元の保護対象リクエストについて所持を検証する認証境界が
必要であり、このサーバーはそのプロトコルを提供しません。

## インストール

```bash
npm install @o3co/auth.policy-verifier.server
```

## パブリック API

### createApp

`createApp(options): Promise<express.Express>` — options の型は [`src/app.mts`](src/app.mts) の `CreateAppOptions` で、そちらが正です。各 knob:

- `pathResolver` — コンポジションルート側の `import.meta.resolve`（または互換リゾルバー）を渡します。モジュール相対パスの解決が必要なモジュールに渡されます。
- `config` — `AppConfig`（[AppConfigSchema](#appconfigschema--appconfig) を参照）。スキーマを通っていない設定も受け付け、実行時に同じ関数で改めて検査します。
- `modules` — サーバーの `ServerModuleContext` で順に初期化されるので、素の core `Module`（collector、rule、parser）も `Module<ServerModuleContext>`（key resolver、token authenticator）も受け付けます。
- `logger`（任意）— 起動時の警告と、verify router の失敗イベント・`decision` イベントを書く構造化ロガー。pino 互換。既定は `config.logging.level` のコンソールロガーで、何も配線しなくても失敗が黙って消えることはありません。

設定済みの Express アプリケーションを組み立てて返します。リスニングは開始しません — 別途 `app.listen(...)` を呼び出してください。

実行ステップ:

1. AttributeCollector・RuleCollector・ResourceParser・key resolver・token authenticator のファクトリ用 `Registry` インスタンスを生成し、どのモジュールよりも先に組み込みの `"jwt"` authenticator を登録する (#219)。
2. `modules` の各モジュールに対して `mod.init(context)` を順に呼び出し、各モジュールがファクトリ関数を登録できるようにする。
3. `config.attribute.collectors` と `config.rule.collectors` の各エントリについて、`collector` 名で登録済みファクトリを検索して AttributeCollector と RuleCollector を生成する。
4. `config.resource.parser` から ResourceParser を、`config.oauth.authenticator` が指す token authenticator を生成する — 組み込みの authenticator は `config.oauth.jwt.algorithm` を key resolver 経由で解決する。
5. metrics middleware をアプリ全体に（すべてを計測するため最初に）マウントし、続いて `config.http.pathPrefix` 以下に liveness probe（`GET /_healthcheck` — スタックの全コンポーネントが応答するパス。`GET /healthcheck` は互換 alias として残す）・`/metrics` スクレイプエンドポイント・任意の caller 認証ゲート・`POST /verify` と `POST /verify/batch` をこの順にマウントする。
6. 設定済みの `express.Express` インスタンスを返す。

### createVerifyRouter

`createVerifyRouter(config: VerifyRouterConfig): express.Router` — `VerifyRouterConfig` はフィールドごとの doc comment 付きで [`src/routes/verify.mts`](src/routes/verify.mts) に定義されており、そちらが正です。`createApp` は `AppConfig` からこれを組み立て、`jwt` ではなく解決済みの `authenticator` を渡します。各 knob の意味:

- **subject の認証 — `jwt` と `authenticator` のちょうど一方** (#219)。両方・どちらもなし・どちらかが `null` は構築時に拒否されます。
  - `jwt` — 組み込みの bearer-JWT 経路で、router 自身が構築します。型は [`src/jwt/tokenAuthenticator.mts`](src/jwt/tokenAuthenticator.mts) の `VerifyRouterJwtConfig` で、`validate` で判別されます: `validate: true` は `key`（`KeyResolverFactory` が返す鍵）、`algorithms`、`issuer`、`audience`、任意の `audienceClaim`（既定 `"aud"`）、`tokenType`（`"*"` は何も pin しない）を持ち、`validate: false` は `allowInsecureDecode: true` を必須とするテスト専用です。どちらの枝も `maxTokenAgeSeconds`（既定 86400）と `clockToleranceSeconds`（0–300、既定 0）を取ります。
  - `authenticator` — 構築済みの `TokenAuthenticator`。`oauth.authenticator` を解決した後に `createApp` が渡すもので、ライブラリ利用者が別の方法で確立した subject の上で router を動かすときに渡すものでもあります。
- `resourceParser`、`attributePipeline`、`rulePipeline` — 必須。collector の上限（`collectorTimeoutMs`、`collectorDeadlineMs`、`collectorConcurrency`）は pipeline 側のもので、この config には含まれません。
- `evaluateOptions` — 評価セマンティクスの上書き。省略時は空 rule set を deny。`ruleTimeoutMs`・`evaluateDeadlineMs`・`failures` をここに含めると構築時に拒否されます: 期限はこの config 自身のフィールドであり、router は判定ごとに 1 つの failure record を持つので (#200)、渡された `failures` はすべての判定で共有されてしまうためです。`signal` は呼び出し元のものと合成され、置き換えられることはありません。
- `maxBatchSize`（既定 50）— `POST /verify/batch` が 1 リクエストで判定する件数の上限。
- `batchConcurrency`（既定 8）— バッチのうち同時に判定する entry 数 (#183)。
- `ruleTimeoutMs`（既定 2000）/ `evaluateDeadlineMs`（既定 5000）— 非同期 Rule 1 つの予算と、1 判定の非同期 Rule 全体の予算 (#225)。超過は `rule_timeout` の deny。
- リクエストの上限 (#118): `maxBodyBytes`（既定 65536。`express.json()` に渡す `limit` で、バッチでは外側の包み）、`maxResourceLength`（既定 512 文字）、`maxActionLength`（既定 64）、`maxContextEntries`（既定 64。`context` のあらゆる深さのプロパティと配列要素をすべて数えるので、深さも縛る）、`maxContextValueLength`（既定 1024 文字。プロパティ名も含む）。
- `logger` — router の失敗イベントと判定ごとの `decision` 行 (#111) の出力先。既定はコンソールロガー。
- `metrics` — 任意の `DecisionMetrics` seam (#111)。省略時は判定はログに出るが計数されない。`createApp` は Prometheus 実装を配線します。
- `credentialToCollectors` — `"never"`（既定）または `"expose"`: 生の credential を `CollectorContext.credential` として collector に渡すか (#175)。
- `evaluationInResponse` — `"omit"`（既定）または `"include"`: response に各 Rule の `evaluation` を載せるか (#244)。それ以外は拒否。

数値の knob はすべて HOCON の環境変数置換が生む文字列形も受け付け、`AppConfigSchema` と同じ範囲で `resolveBound` が読みます (#157)。

`POST /verify` と `POST /verify/batch` を処理する Express Router を返します。`createApp` が内部で呼び出すため、通常は直接使用する必要はありません。ルーターを独立してマウントしたい場合のみ直接利用してください。

リクエスト処理フロー:

1. トークンを見る前にボディを検証する (#118): `resource` を `resourceParser` でパースし、`action` と `context` を読み取り、そのすべてをリクエストの上限に照らす。失敗時は `400 invalid_request` を返す — つまり不正なリクエストは、有効なトークンを持っていなくても 400 になる。
2. `Authorization` ヘッダーを authenticator に渡す。組み込みの authenticator（`jwt`）は `Bearer <token>` を取り出し（スキームは大文字小文字を区別せずに照合）、ヘッダーが存在しないかスキームが Bearer でない場合は 401 を返す。直接渡された `authenticator` は自身の `code` / `message` で応答し、ステップ 3〜5 はその authenticator の責務になる。
3. `validate` が `true` の場合: 署名に加えて RFC 9068 §4 のクレームを検証する — `iss` を `issuer` と、audience クレーム（`aud`、または `audienceClaim` が指すクレーム）を `audience` と、`typ` ヘッダを `tokenType` と照合する（`application/` プレフィックスは無視。`"*"` は何も pin しない）。失敗時は 401 を返す。3 つのいずれかが欠けている場合、`createVerifyRouter` は例外を投げる。
4. `validate` が `false` の場合: JWT を検証なしでデコードする。不正なトークンの場合は 401 を返す。
5. どちらの経路でもトークン自身の寿命を検証する: `exp` と `iat` は**必須**（有効期限を宣言しないトークンは失効しない）、`nbf` は存在すれば検証、`exp` は未来でなければならず、`now - iat` は `maxTokenAgeSeconds` を超えてはならない — 発行者が何年も先の `exp` を付けたトークンを拒否するのはこれ。`clockToleranceSeconds` はこれら全ての比較に効く。失敗時は 401 を返す。デコード専用経路はこれらの検査を省略せず手書きで再現するので、同一トークンに対して両モードの答えは一致する。
6. `x-request-id` ヘッダーが存在し、受け入れられる形であれば `CollectorContext.headers` に含める（コレクターが上流呼び出し時に転送可能）。受け入れられるのは `A-Z a-z 0-9 - _ . : + / = #` からなる 1〜128 文字（`acceptRequestId`、#200）で、それ以外の値はここでもログ行でもレスポンスでも無かったものとして扱う。受け入れた ID は、手順 1〜5 の拒否を含め router が書くすべてのレスポンスに `x-request-id` レスポンスヘッダとして返し、呼び出し元が送らなかった場合に採番することはない。
7. `attributePipeline.collect` と `rulePipeline.collect` を collector の上限（`verify.collectorTimeoutMs` / `verify.collectorDeadlineMs` / `verify.collectorConcurrency`。各 collector には `CollectorContext.signal` で `AbortSignal` が渡される）のもとで並列実行し、`evaluate` を呼び出す。
8. `200 { decision: "allow" }` または `403 { decision: "deny", code, message }` を返す。
9. collector または fan-out が時間切れになった場合は `403 { decision: "deny", code: "collector_timeout" }` を返す (#115)。評価器には到達させない — 一部の Rule しか集まらないことはポリシーが弱いことであり、1 つも集まらなければ `rule.onEmptyRuleSet = "allow"` では allow になるため。タイムアウトは deny にしかなり得ない。詳細は呼び出し側ではなく `collector_timeout` ログ行に出る — `category: "collector_timeout"` と、予算を超えた `collector`（`attribute.collectors[1] (EntitlementStoreCollector)`）、pipeline のデッドラインを超えた場合はリストそのもの（`attribute.collectors`）(#200)。
10. 非同期 Rule が `verify.ruleTimeoutMs` 以内に応答しなかった場合 (#225)、または非同期 Rule 全体で `verify.evaluateDeadlineMs` を超えた場合は `403 { decision: "deny", code: "rule_timeout" }` を返す — 同じ deny だが専用の code を持つので、運用者は停止したのがエンジンなのか collector なのかを区別できる。`rule_timeout` ログ行は `category` と `rule`（`{ ruleType, code }`）を持つ。
11. 予期しないエラーが発生した場合は `500 { decision: "deny", code: "internal_error" }` を返し、`verify_internal_error` としてログに出す。行は `endpoint`、ID があれば `requestId`、そして `category` を持つ (#200): `collector` を名指しする `collector_threw`、`rule` を名指しする `rule_threw`、エンベロープが対応付けていない body parser の失敗の `body_rejected`、decision から出てきたのではないものの `internal`。collector と rule は router が decision ごとに持つ `FailureRecord` に記録されたもので、エラーから読んだ名前ではない。ルールの `ruleType` と `code` は識別子の形の場合だけ記録され、それ以外は `redacted` になる。閉じた集合は `FAILURE_CATEGORIES` として export され、そのうちコレクターの失敗は `DecisionMetrics.observeCollectorFailure` で計上される（`createApp` では `auth_collector_failures_total{collector,category}`）。

### AppConfigSchema / AppConfig

`AppConfigSchema`（zod）と `AppConfig`（その推論型）は、knob ごとの doc comment 付きで [`src/config/application.schema.mts`](src/config/application.schema.mts) に定義されており、そちらが正です。数値 knob の既定値・範囲・単位は [`src/config/bounds.mts`](src/config/bounds.mts) の `NUMERIC_BOUNDS` に一度だけ記述され、それ以外の既定値は [`src/config/defaults.mts`](src/config/defaults.mts) にあります。各キーに対応する環境変数まで注記した HOCON 形は、ルート README の [設定](../../README.ja.md#設定) 節にあります。

トップレベルのセクション:

- `http` — どこで listen し、誰が呼べるか: `hostname`（既定 `127.0.0.1`。[信頼境界](#信頼境界) を参照）、`port`（既定 3000）、`pathPrefix`、任意の `callerAuth`（`header` — 既定 `x-caller-token` — と `token`）。ブロックごと省略できます。
- `oauth` — subject をどう認証するか。`authenticator` が token authenticator を名指しします（既定 `"jwt"`、またはモジュールが登録した名前、#219）。`"jwt"` のときは `jwt` ブロックが必須で、組み込みの bearer-JWT 経路を設定します — アルゴリズムと鍵素材、`mode`（`"verify"` またはテスト専用の `"insecure-decode"`）、`issuer` / `audience` / `audienceClaim` / `tokenType`、トークン寿命の上限。それ以外の名前では `jwt` ブロックは拒否され、その authenticator 自身のサブブロック（`oauth.<name>`）はパースされずにそのまま渡り、ファクトリが検証します。
- `attribute.collectors` / `rule.collectors` — 必須の collector エントリのリスト。下記を参照。
- `rule.onEmptyRuleSet` — `"deny"`（既定）または `"allow"`: Rule が 1 つも集まらなかったときの判定。
- `resource.parser` — 登録済みの resource parser 名（既定 `DotNotationResourceParser`）。
- `verify` — 判定エンドポイントの上限と開示範囲。`createApp` は collector の上限（`collectorTimeoutMs`、`collectorDeadlineMs`、`collectorConcurrency`）を自身が組み立てる pipeline に渡し、残り — `maxBatchSize`、`batchConcurrency`、リクエストの上限、`ruleTimeoutMs` / `evaluateDeadlineMs`、`credentialToCollectors`、`evaluationInResponse` — を [`createVerifyRouter`](#createverifyrouter) に渡します。各 knob の意味は上のリストを参照してください。ブロックごと省略でき、すべての knob に既定値があります。
- `logging.level` — コンソールロガーの閾値（既定 `info`）。

**数値ノブはすべて、両方の境界で 1 つの関数から読まれます** (#157)。`boundedNumber` は
[`config/bounds.mts`](src/config/bounds.mts) の `resolveBound` をラップしたもので、各ノブの既定値・
範囲・単位は `NUMERIC_BOUNDS` に一度だけ記述されます。ランタイム側のガード（`createApp`、
`createVerifyRouter`、各 `KeyResolverFactory`）は手組み config のために `resolveBound` を直接呼ぶため、
両境界は同じ判定を同じ文言で返します。`z.coerce.number()` ではないのは意図的です: ノブは数値か、
HOCON の `${?VAR}` 置換が渡す文字列のいずれかで到着し、その両方を受け付けますが、`z.coerce` は
`true` を `1`、`null` と `""` を `0` として読んでしまいます — 空で export された環境変数が「意図的な
ゼロ」になっていたのはこれが原因でした。非整数・`NaN`・`Infinity` も同じ理由で拒否します。

`attribute.collectors` と `rule.collectors` の各エントリには `collector` フィールド（登録済みファクトリ名）が必須です。追加フィールドはファクトリへの設定としてそのまま渡されます。

**HS256 のシークレットは鍵素材として 32 バイト（256 ビット）以上を持つこと。** この下限は `oauth.jwt.secret` と `oauth.jwt.previousSecrets[].secret` の全件に 1 つのルールとして適用されます — 退役したシークレットも重複期間中は検証鍵であり、現行と同じようにトークンを発行できるからです。判定はデコード後の素材に対してもっとも小さく読める解釈で行うため、16 進 64 文字は通り（32 バイト）、16 進 32 文字は通りません（16 バイト）。生成は `openssl rand -hex 32`。`AppConfigSchema` が config パース時に拒否し、HS256 の `KeyResolverFactory` が hand-built config のために同じ検査を繰り返します。独自の HS256 key resolver を登録する利用者向けに `measureSecretEntropyBytes` / `describeWeakSecret` / `MIN_SECRET_ENTROPY_BYTES` を公開しています。`createVerifyRouter` は鍵素材を直接受け取るため下限を適用しません — `KeyObject` を自分で組み立てる呼び出し側がその検査を負います。

### 信頼境界

`/verify` の Bearer トークンが確立するのは、判定の対象となる **subject** だけです。`resource` / `action` / `context` を誰が渡したのかについては何も語りません。したがって subject トークンしか検査しないエンドポイントは decision oracle になります — ポートに到達できる者は誰でも、そのデプロイがどのトークン・スコープ・リソースを受け入れるのかを探れますし、その過程で collector パイプラインを走らせられます。

これを抑えるのが次の 2 つの設定です。

- **`http.hostname` の既定値は `127.0.0.1`。** 本プロジェクトが想定するのはサイドカー構成 — enforcement 層が verifier と同居し、ループバック経由で到達する形です。全インターフェースへの bind は明示的なオプトイン（`http.hostname = "0.0.0.0"`）であり、コンテナデプロイではこれを設定しない限り到達できません。
- **`http.callerAuth.token` は呼び出し元サービスを認証します。** 設定すると、`/verify` と `/verify/batch` への全リクエストがその値を `http.callerAuth.header`（既定 `x-caller-token`。`Authorization` を避けているのは意図的）にそのまま載せる必要があります。比較は定数時間で、body のパースより前・パイプライン処理より前に走るため、未認証のピアはプロセスの処理時間を消費できません。資格情報の欠落と誤りは同一の `401 { decision: "deny", code: "caller_unauthenticated", message: "Caller authentication failed" }` を返します — 推測した値が正しい形だったかを探索者に教えてはならないからです。`GET /_healthcheck` は常に非ゲートで、オーケストレーターの probe はそのまま動作します。

caller 認証は**本リリースでは任意**です。未設定かつ bind がループバックでない場合、`createApp` は `unauthenticated_non_loopback_bind` を warn で記録します。ログには関係する 2 つの設定・何が晒されているか・どう対処するかが載ります:

```json
{"level":40,"msg":"unauthenticated_non_loopback_bind","hostname":"0.0.0.0","bindSetting":"http.hostname","callerAuthSetting":"http.callerAuth","exposure":"POST /verify and /verify/batch answer authorization decisions to any caller that can reach this port with a valid subject token — the endpoint is a decision oracle","remediation":"restrict the port to a private network, or set http.callerAuth.token (env HTTP_CALLER_AUTH_TOKEN) so the calling service authenticates itself"}
```

起動を拒否せず warn に留めています。ネットワーク側が正当な制御になっている場合があり（プライベートサブネット、Pod ローカルのサービス、mesh のポリシーなど）、プロセスからはそれが見えません。分かるのは bind するよう指示されたアドレスだけです。ここで拒否すれば、下せる立場にない判断と引き換えに、アップグレード時に既存のコンテナデプロイをすべて壊すことになります。caller 認証の必須化は `config/defaults` の `CALLER_AUTH_REQUIRED` の 1 行変更です — 全体に対して一度だけ行う、意図的な breaking change です（同定数の doc コメント参照）。

**推奨する構え（優先順）。** いずれかを選んでください。2 つ組み合わせればさらに良いです。

1. **bind をループバックのままにする。** サイドカー構成です。enforcement 層が同一ホスト（あるいは同一 Kubernetes Pod のネットワーク名前空間）に同居し、`127.0.0.1:3000` に到達します。設定も資格情報のローテーションも不要で、既定がすでにこの形です。
2. **ループバック以外に bind せざるを得ない場合は、ネットワーク層でポートを制限する** — プライベートサブネット、セキュリティグループ、`NetworkPolicy` など。コンテナのポート publish はこれに**該当しません**: `HTTP_HOSTNAME=0.0.0.0` と `ports: ["3000:3000"]` の組み合わせは、そのホストに到達できるすべてに到達を許します。
3. **併せて `http.callerAuth.token`（env `HTTP_CALLER_AUTH_TOKEN`）を設定する。** ポートに到達できるだけでは判定を要求できなくなります。3 つのうち、攻撃者が既にネットワーク境界の内側にいる場合でも有効なのはこれだけです。なお Go の enforcement 層（[protobuf.interceptors](https://github.com/o3co/protobuf.interceptors)）は v0.3.0 以降、`endpoint.WithO3coHeaders` でこのヘッダを送れます。それより前のバージョンで作られた呼び出し元は 1 か 2 を使ってください。

共有資格情報はネットワークポリシーや enforcement 層との mTLS の代替ではありません。下限であって上限ではありません。

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

**`evaluation`（#244）。** policy evaluator を背後に持つ Rule（`CedarPolicyRuleCollector`）は、answer ごとに
「evaluator が走ったか」「どの policy revision を評価したか」を報告し、その outcome には `passed` の隣に
`"evaluation": { "status": "completed", "revision": "sha256:…" }` が載ります。`decision` ログイベントには
常に `evaluations` として並びます。response に載るのは `verify.evaluationInResponse = "include"` のときだけで、
既定の `"omit"` では上の response はキー単位でそのままです。evaluation は、受理される token の保持者全員に
「policy set がいつ変わったか」「deny が engine の失敗だったか」を伝えるからです。各形の意味と、アプリケーションが
保存すべきものは、ルート README の [どの policy revision が決めたかを記録する](../../README.ja.md#どの-policy-revision-が決めたかを記録する) にあります。

**レスポンス — 不正なリクエスト**

```http
HTTP/1.1 400 Bad Request

{ "decision": "deny", "code": "invalid_request", "message": "<message>" }
```

`resource` / `action` が欠落・空・文字列でない場合、`context` がオブジェクトでない場合、および `resource` が
設定された `ResourceParser` に拒否される文字列だった場合に返します。後者はサーバー側の障害ではなく呼び出し側の
構文エラーなので、500 ではなく 400 で応答し、`verify_internal_error` としてもログしません。
`DotNotationResourceParser` では空セグメント (`a..b`)、セグメント内の 2 つ目の `:` (`a:1:2`)、空白 (`  a:1  `)
が該当します。文法は [builtins README](../builtins/README.ja.md#dotnotationresourceparser) を参照してください。
ボディの検証は decision の前に行われるため、ここで拒否されたリクエストは 1 件も評価されません。

**レスポンス — 予期しないエラー**

```http
HTTP/1.1 500 Internal Server Error

{ "decision": "deny", "code": "internal_error" }
```

**レスポンスヘッダ — `x-request-id`**

リクエストが `A-Z a-z 0-9 - _ . : + / = #` からなる 1〜128 文字の ID を送った場合、上記のすべてのレスポンスは `x-request-id: <送られた ID>` を持ち、それ以外の場合はこのヘッダを持ちません (#200)。ID は呼び出し元のもので、enforcement 層が判定（や `500`）を自分のログと突き合わせられるように返すものです。サーバーが採番することはありません。

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
呼び出し側が各エントリを読みます。エントリは一度に最大 `verify.batchConcurrency` 件（既定 8）ずつ
決定されます (#183) — collector の上限は decision 単位なので、これが 1 バッチに
`maxBatchSize × collectorConcurrency` 本の collector を同時に持たせないための上限です。`decisions` が無い / 空 / `verify.maxBatchSize` 超過 / 不正なエントリ
（`resource` がパーサーに拒否されたものを含む）を含む場合は `400 invalid_request`（メッセージが該当 index を
示します）、トークンが検証できない場合は `401` でバッチ全体を拒否します。バッチは 1 件も判定する前に全件を
検証するため、1 件の不正なエントリは部分的な回答ではなくリクエスト全体の拒否になります。

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

同じ context は `tokenAuthenticatorRegistry` も運びます (#219)。`createApp` はどのモジュールよりも先にそこへ組み込みの `"jwt"` authenticator を登録します。モジュールは自分の名前で `TokenAuthenticatorFactory` を登録し — introspection クライアント、IdP SDK、ゲートウェイの attestation など — `oauth.authenticator` でそれを選択します。その場合 `oauth.jwt` は省略できます。[docs/extending.ja.md — token authenticator の書き方](../../docs/extending.ja.md#token-authenticator-の書き方) を参照してください。

## 関連

- [`@o3co/auth.policy-verifier.core`](../core/README.ja.md) — 型定義、`evaluate`、`AttributePipeline`、`RulePipeline`、Module インフラ
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.ja.md) — 組み込みコレクターとパーサー
- [auth.policy-verifier ルート README](../../README.ja.md) — アーキテクチャ概要・設定リファレンス・Docker
