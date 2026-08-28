# auth.policy-verifier

[![CI](https://github.com/o3co/auth.policy-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.policy-verifier/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/auth.policy-verifier.core)](https://www.npmjs.com/package/@o3co/auth.policy-verifier.core)
[![codecov](https://codecov.io/gh/o3co/auth.policy-verifier/graph/badge.svg)](https://codecov.io/gh/o3co/auth.policy-verifier)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> このリポジトリは、[auth](https://github.com/o3co/auth) スタックの 3 層責務分離（[認証・トークン発行](https://github.com/o3co/auth.provider) / 認可判定 / [認可実施](https://github.com/o3co/protobuf.interceptors)）のうち **認可判定** を担当します。

マイクロサービス認可のための属性ベースアクセス制御 (ABAC) エンジン。JWT + リソース + アクションを受け取り、Collector 駆動のルールを評価して allow/deny を返す。ポリシー DSL 不要 — 認可ロジックは TypeScript で組み立てる。

- OPA や Cedar にドロップイン置き換え可能 — [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) は共通の `VerifierEndpoint` インターフェース経由で本サービス、OPA、Cedar Agent のいずれにもルーティング可能
- HTTP サイドカーとして動作 — エンジンの差し替えはコード変更ではなく設定変更で完了
- JWT 検証アルゴリズム設定可能 — HS256, RS256, ES256, EdDSA。JWKS または公開鍵直接指定に対応。

## 仕組み

```text
POST /verify
Authorization: Bearer <jwt>
{"resource": "project:1", "action": "read"}

  ┌──────────────────────────────────────────────────┐
  │                  /verify ハンドラ                  │
  │                                                   │
  │  1. body 検証 (上限・文法・未知キー)               │
  │                                                   │
  │  2. JWT 検証 (HS256 / RS256 / ES256 / EdDSA)     │
  │                                                   │
  │  3. AttributeCollectors (並列)                    │
  │     ├─ PayloadScopeCollector → JWT からスコープ   │
  │     ├─ PayloadSubjectIdCollector → サブジェクトID  │
  │     └─ (カスタム Collector...)                    │
  │                                                   │
  │  4. RuleCollectors (並列)                         │
  │     ├─ ResourceActionScopeRuleCollector            │
  │     │   → HasScope("read:project")                │
  │     └─ (カスタム RuleCollector...)                │
  │                                                   │
  │  5. 評価                                          │
  │     ルールグループ内は OR、グループ間は AND          │
  │     全グループを評価 → 構造化 reason                │
  │                                                   │
  │  → 200 {"decision": "allow",  "reason": {...}}    │
  │  → 403 {"decision":"deny","code":…,"reason":{…}} │
  └──────────────────────────────────────────────────┘

POST /verify/batch — 同じ契約で、1 往復に N 件の decision
{"decisions": [{"resource": "project:1", "action": "read"}, …]}
  → 200 {"decisions": [{…}, …]}   (順序は保持。全部 deny でも 200)
```

ステップ 1 はステップ 2 の **前** に走る。不正な body は資格情報の有無にかかわらず
`400 invalid_request` であり、body で拒否されたリクエストでは Collector は 1 つも動かない。
その順序の理由と、匿名の呼び出し元が何を知り得るかは [リクエストの上限](#リクエストの上限) を参照。
上図のステータス・コード・レスポンスキーを含む wire 契約全体は
[`tests/integration/src/conformance/`](tests/integration/src/conformance/) が固定しており、
そのフィクスチャは JSON なので enforcement 層は同じ表に対して実装できる。

## 特徴

- **Collector パターン** — 属性とルールはコンポーザブルな Collector で収集。静的なポリシーファイルではない。任意の属性ソース（DB, 外部 API, JWT クレーム）向けにカスタム Collector を追加可能。
- **boolean ではなく decision 契約** — リクエストは `(subject, resource, action, context)`、応答は各ルールグループとその結果を並べた構造化 `reason` を必ず伴う。「なぜ deny されたか」をパイプラインの再実行なしに答えられる。`POST /verify/batch` は複数リソースを 1 往復で判定する。
- **JWT 検証アルゴリズム設定可能** — HS256（共有シークレット）、RS256/ES256/EdDSA（JWKS URI または公開鍵直接指定）。[auth.provider](https://github.com/o3co/auth.provider) の JWT 設定と対称設計。
- **RFC 9068 §4 のトークン検証** — 署名だけでなく `iss` / `aud` / `typ` ヘッダも検証する。同じ鍵で署名された `id_token` / refresh token / logout token や、他サービス向けに発行されたトークンは拒否される。`mode = "verify"`（デフォルト）のとき `issuer` と `audience` は必須。
- **トークン寿命の上限** — `exp` と `iat` は「あれば検証する」ではなく**必須**。さらに `maxTokenAgeSeconds` が、発行者がどれだけ先の `exp` を付けたかに関わらず「発行からどれだけ経ったトークンまで受け入れるか」の上限を課す。`exp` を持たずに発行（あるいは偽造）されたトークンは、永久に有効ではなく拒否される。`clockToleranceSeconds`（デフォルト 0、上限 300）はクロックずれの許容幅。これらはすべて `insecure-decode` モードでも同じく適用されるので、2 つのモードが同一トークンについて食い違うことはない。
- **JWKS サポート** — `jwksUri` を auth.provider の `https://.../.well-known/jwks.json` に向ければ鍵ローテーションに自動対応。エンドポイントは TLS 必須（ローカル開発向けにループバックのみ例外）。取得はタイムアウト / クールダウン / キャッシュ期間で必ず上限が付き、プロバイダー障害が判定パスを止めない。
- **本番で答えられる** — 判定 1 件ごとに構造化された `decision` イベント（subject / resource / action / 決め手になったルール / request id / レイテンシ）を出力し、allow/deny カウンタを持つ Prometheus `/metrics` を提供する。メトリクスのラベルはすべて有界であり、bearer トークン・`sub` を超えるクレーム集合・呼び出し元の `context` はログに載らない。[可観測性](#可観測性)を参照。
- **プラグイン可能なアーキテクチャ** — Module システムでカスタム Collector、ルール、リソースパーサーをファクトリ経由で登録。
- **DSL ロックインなし** — 認可ロジックは TypeScript。Rego も Cedar ポリシー言語も不要。スケールアウトが必要になれば [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) 経由で OPA や Cedar に差し替え可能 — interceptor がバックエンドを抽象化する。

## いつ選ぶか

- ポリシーを書くのは開発者で、DSL を学習したくない → **これ**
- ポリシーを非開発者が編集する、または形式検証が必要 → **[Cedar](https://www.cedarpolicy.com/)**
- 組織全体のポリシー基盤として広範な built-in operator 群が必要 → **[OPA](https://www.openpolicyagent.org/)**

## Quick Start

```bash
npx @o3co/create-auth-policy-verifier my-policy-verifier
cd my-policy-verifier
pnpm install
OAUTH_JWT_SECRET=$(openssl rand -hex 32) \
  OAUTH_JWT_ISSUER=https://issuer.example.com \
  OAUTH_JWT_AUDIENCE=https://api.example.com \
  pnpm start
```

HS256 シークレットは鍵素材として **32 バイト（256 ビット）以上**を要求し、これを下回ると起動を拒否する — 詳細は [HS256 シークレットのローテーション](#hs256-シークレットのローテーション)。auth.provider が署名に使うのと同じ値を設定すること。

```bash
curl -X POST http://localhost:3000/verify \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"resource": "project:1", "action": "read"}'
```

```json
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
        "evaluated": [{ "code": "invalid_scope", "message": "…", "passed": true }],
        "satisfiedBy": { "code": "invalid_scope", "message": "…", "passed": true }
      }
    ]
  }
}
```

リスト絞り込みはリソースごとではなく 1 往復で済む:

```bash
curl -X POST http://localhost:3000/verify/batch \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"decisions": [
        {"resource": "project:1", "action": "read"},
        {"resource": "project:2", "action": "read"}
      ]}'
```

```json
{"decisions": [{ "resource": "project:1", "decision": "allow", "…": "…" }]}
```

## アーキテクチャ

```text
standalone → server   → core
          → builtins  → core
```

- **core** — 型定義、`evaluate()`、`AttributePipeline`、`RulePipeline`、Module 基盤。ランタイム依存なし。エンジン中立な入力: core が受け取るのは `(subject, resource, action, requestContext)` で、`subject` は属性バッグ — core は JWT を一切知らない。デフォルト server が検証済み JWT クレームからバッグを組み立てる。このマッピングが server の境界に置かれていることが、エンジン差し替え可能性の担保。
- **builtins** — 組み込み Collector (scope, permission, role, subject ID)、ルール (HasScope, HasPermission, 属性比較ルール)、DotNotation リソースパーサー。server に依存しない。カスタム Rule / Collector の書き方は [`docs/extending.ja.md`](docs/extending.ja.md) を参照。
- **server** — Express HTTP サーバー、`createApp()`、`POST /verify` ルート、JWT 鍵解決、設定スキーマ。builtins に依存しない。
- **standalone** — コンポジションルート: HOCON 設定読み込み、モジュール選択、サーバー起動。

## パッケージ構成

| パッケージ | npm | 説明 |
| --- | --- | --- |
| [`packages/core`](packages/core/) | `@o3co/auth.policy-verifier.core` | 型定義、evaluate、パイプライン、Module 基盤 |
| [`packages/builtins`](packages/builtins/) | `@o3co/auth.policy-verifier.builtins` | 組み込み Collector、ルール、リソースパーサー |
| [`packages/server`](packages/server/) | `@o3co/auth.policy-verifier.server` | Express サーバー、`createApp`、`POST /verify`、JWT 鍵リゾルバ |
| [`templates/standalone`](templates/standalone/) | — | デプロイ可能なサーバーテンプレート (コンポジションルート) |
| [`create-app`](create-app/) | `@o3co/create-auth-policy-verifier` | CLI スキャフォルダー |

## 評価ロジック

ルールは `ruleType`（例: "scope", "permission"）でグループ化:

- **グループ内:** OR — 1つでも通ればそのグループは通過
- **グループ間:** AND — 全グループが通過する必要あり

最初に失敗したグループ以降も含め、**全グループを評価する**。決定には各グループの通過可否と、
そのグループで実際に走ったルールを評価順に並べた `evaluated` を持つ `reason` が付く。
通過グループは最初に通ったルールで評価を打ち切り、そのルールを `satisfiedBy` として明示する。
失敗グループは全代替ルールを走らせている。途中で打ち切ると「残りのグループも失敗したのか」に
答えられず、それこそが deny の説明が存在する理由だからである。ルールは契約上 attributes の純関数なので
全部走らせても安全。deny の `code` / `message` は従来どおり最初に失敗したグループから取る。


ルールが 1 つも集まらなかった場合 → **deny**。どのルールも適用されなかったリクエストは「認可されていない」ので、
`no_applicable_rule` で拒否する (OPA / OpenFGA / Cedar の implicit deny と同じ挙動)。
`rule.onEmptyRuleSet = "allow"` を明示するとこの既定を opt-out して fail-open にできるが、認可を別レイヤで
担保している場合に限る。RuleCollector が 1 つも設定されていない場合は起動時に失敗する。

### 組み込みルール

| ルール | 生成元 | マッチ条件 |
| --- | --- | --- |
| `HasScope("read:project")` | `ResourceActionScopeRuleCollector` | JWT の `scope` クレームに `read:project` が含まれる |
| `HasPermission("project:1.perm:read")` | `ResourceActionPermissionRuleCollector` | ユーザーの permissions/roles にマッチするパターンが含まれる（`*` ワイルドカード対応） |

RuleCollector だけではポリシーになりません。ルールグループは AND で評価されるため、
属性を供給する AttributeCollector なしに有効化すると、何をもってしても満たせない
グループができ、全リクエストを拒否する verifier になります。
`ResourceActionPermissionRuleCollector` は `permissions` / `roles` を書く
コレクターと同じ編集でセットにしてください。

### 組み込み AttributeCollector

| Collector | 読む | 書く |
| --- | --- | --- |
| `PayloadScopeCollector` | JWT `scope` クレーム | `scopes` |
| `PayloadSubjectIdCollector` | JWT `sub` クレーム | `userId` |
| `StaticPermissionCollector` / `StaticRoleCollector` | config の定数 | `permissions` / `roles` |
| `RequestContextAttributeCollector` | リクエスト `context` の宣言済みフィールド | 運用者が決めたキー |

## 設定

HOCON 設定 + 環境変数オーバーライド:

```hocon
http {
  port = 3000
  port = ${?HTTP_PORT}
}

oauth {
  jwt {
    algorithm = "HS256"           # HS256 | RS256 | ES256 | EdDSA
    algorithm = ${?OAUTH_JWT_ALGORITHM}

    # ---- HS256 専用。以下 2 グループのどちらか一方だけを使うこと。 --------
    secret = ${?OAUTH_JWT_SECRET}            # デコード後 32 バイト以上 — `openssl rand -hex 32`
    kid = ${?OAUTH_JWT_KID}                  # 上の secret に名前を付ける。未設定ならトークンヘッダを参照しない
    # previousSecrets — 重複期間中の旧シークレット、最大 3 件。ここにあえて
    # 書いていない: このキーは RS256/ES256/EdDSA では（空リストであっても）
    # 起動時に拒否されるため、どのアルゴリズムでもコピーされうるスニペットに
    # 置いてはならない。HS256 のときだけ追加すること:
    #   previousSecrets = [
    #     { kid = "v0", secret = ${?OAUTH_JWT_PREVIOUS_SECRET}, expiresAt = "2026-09-01T00:00:00Z" }
    #   ]

    # ---- RS256 / ES256 / EdDSA 専用 --------------------------------------
    jwksUri = ${?OAUTH_JWT_JWKS_URI}         # https 必須、例: https://auth-provider/.well-known/jwks.json
    jwksTimeoutMs = 5000                     # JWKS 取得の上限 — 打ち切り時間
    jwksCooldownMs = 30000                   # 再取得の最小間隔
    jwksCacheMaxAgeMs = 600000               # 取得済み JWKS のキャッシュ期間
    publicKey = ${?OAUTH_JWT_PUBLIC_KEY}     # PEM 文字列
    publicKeyPath = ${?OAUTH_JWT_PUBLIC_KEY_PATH}  # またはファイルパス

    # ---- 全アルゴリズム共通 ----------------------------------------------
    issuer = ${?OAUTH_JWT_ISSUER}           # mode = "verify" のとき必須 — RFC 9068 §4 iss
    audience = ${?OAUTH_JWT_AUDIENCE}       # mode = "verify" のとき必須 — RFC 9068 §4 aud
    tokenType = "at+jwt"                     # 受け入れる typ ヘッダ
    tokenType = ${?OAUTH_JWT_TOKEN_TYPE}
    maxTokenAgeSeconds = 86400               # now - iat の上限。設定により iat が必須になる
    clockToleranceSeconds = 0                # クロックずれ許容幅 0–300。provider に合わせるなら 60
    mode = "verify"                          # "verify"（デフォルト）| "insecure-decode"（テスト専用）
    mode = ${?OAUTH_JWT_MODE}
  }
}

attribute {
  collectors = [
    { collector = "PayloadScopeCollector" }
    { collector = "PayloadSubjectIdCollector" }
    # リクエストボディの `context` から宣言済みフィールドだけを属性に昇格させる。
    # 宣言していないフィールドは昇格されず、宣言した型に合わない値は捨てられる。
    { collector = "RequestContextAttributeCollector"
      attributes = [
        { from = "tenant.id", to = "tenantId" }
        { from = "groups", type = "string[]" }
      ] }
  ]
}

rule {
  onEmptyRuleSet = "deny"       # deny | allow — ルールが集まらなかったときの決定
  onEmptyRuleSet = ${?RULE_ON_EMPTY_RULE_SET}
  collectors = [
    { collector = "ResourceActionScopeRuleCollector" }
  ]
}

resource {
  parser = DotNotationResourceParser
}

verify {
  maxBatchSize = 50             # POST /verify/batch の件数上限
  maxBatchSize = ${?VERIFY_MAX_BATCH_SIZE}
  maxBodyBytes = 65536          # JSON ボディの上限。超過は 413 payload_too_large
  maxBodyBytes = ${?VERIFY_MAX_BODY_BYTES}
  maxResourceLength = 512       # `resource` の文字数
  maxResourceLength = ${?VERIFY_MAX_RESOURCE_LENGTH}
  maxActionLength = 64          # `action` の文字数
  maxActionLength = ${?VERIFY_MAX_ACTION_LENGTH}
  maxContextEntries = 64        # `context` 全体のプロパティ数 + 配列要素数（深さを問わず）
  maxContextEntries = ${?VERIFY_MAX_CONTEXT_ENTRIES}
  maxContextValueLength = 1024  # `context` 内の文字列の文字数（キー名を含む）
  maxContextValueLength = ${?VERIFY_MAX_CONTEXT_VALUE_LENGTH}

  # 各決定で 2 つの pipeline が走らせる collector fan-out の上限 (#115)。
  # いずれかを超えた決定は deny になる — 部分的な結果は決して返さない。
  # 下記「コレクターのデッドライン」を参照。
  collectorTimeoutMs   = 2000   # コレクター 1 本あたりの予算
  collectorTimeoutMs   = ${?VERIFY_COLLECTOR_TIMEOUT_MS}
  collectorDeadlineMs  = 5000   # pipeline 単位の fan-out 全体
  collectorDeadlineMs  = ${?VERIFY_COLLECTOR_DEADLINE_MS}
  collectorConcurrency = 8      # 同時に走らせるコレクター数
  collectorConcurrency = ${?VERIFY_COLLECTOR_CONCURRENCY}
}
```

### リクエストの上限

呼び出し側が決める入力はすべて上限を持ち、その上限が上のノブです。`maxBodyBytes` は外枠 —
`express.json()` の limit で、Express の暗黙の 100 KB デフォルトより小さい — であり、大きなバッチでは
これが最初に効きます。フィールドごとの上限が縛るのは *1 件* であって N 件の合計ではないためです。
`maxContextEntries` は `context` ツリー全体のプロパティと配列要素をすべて数えるので、ネストは禁止では
なく上限が付きます (`RequestContextAttributeCollector` は `tenant.id` のようなドットパスを読みます)。
ネスト 1 段につき最低 1 エントリを消費するため、これは深さの上限にもなります。

明示しておくべき拒否が 3 つあります:

- **`resource` / `action` の空白は trim せず拒否** — リソース文法がすでに適用している方針を、`action` と
  独自パーサーを登録したデプロイにも広げたものです。どちらも発行者が grant した
  `{action}:{resourceType}` scope に連結され、RFC 6749 §3.3 では空白が scope 値の区切り文字です。
- **未知のプロパティは拒否** — `{"resource": "project:1", "action": "read", "subject": "admin"}` は、
  `subject` を黙って無視した決定ではなく `400 invalid_request` になります。subject は検証済みトークン
  由来であってボディ由来ではなく、拒否することが呼び出し側にそれを伝える唯一の手段です。
- **トークン検証より先にボディを検証** するため、トークンの有無にかかわらず不正なボディは `400` です。
  ボディの検査は上の上限で有界ですが、トークン検証はネットワークに到達しうる側です。したがって匿名の
  呼び出し側もボディが正しい形かどうかは知ることになります。それすら開示できないデプロイのゲートが
  `http.callerAuth` です。

パーサー自身が拒否したボディも、他と同じ deny エンベロープで答えます。Express の HTML
エラーページに落ちることはありません:

```json
{"decision": "deny", "code": "invalid_request", "message": "Request body is not valid JSON"}
```

不正な JSON は `400`、`maxBodyBytes` 超過は `413 payload_too_large`、読めない Content-Type /
charset は `415 unsupported_media_type` です。上の例はレスポンスボディそのもので、この 1 行が
`README.md` / `README.ja.md` / `CHANGELOG.md` に現れ、かつエンドポイントが実際に返す内容へ
parse されることを `verifyInputValidation.test.mts` が検証しています。3 か所のコピーがコードから
も互いからも drift しないのはそのためです。

### コレクターのデッドライン

Attribute / Rule コレクターはデータベースや HTTP API を呼ぶ層であり、つまり停止しうる層です。fan-out は 3 つの上限で守られており、既定で有効です — 何も設定していない deployment にも適用されます:

| 設定キー | 既定値 | 何を制限するか |
| --- | --- | --- |
| `verify.collectorTimeoutMs` | `2000` | コレクター 1 本の所要時間。予算はそのコレクターが**開始した時点**から数えるので、同時実行上限による順番待ちで消費されることはない |
| `verify.collectorDeadlineMs` | `5000` | pipeline 単位の fan-out 全体の所要時間。個々の予算は超えていないのに合計では超えている、というケースを捕える |
| `verify.collectorConcurrency` | `8` | 1 決定・1 pipeline あたりの同時実行数。現実的なコレクター構成より大きいので通常は何も変わらず、依存先が遅くなって処理が積み上がり始めたときだけ効く |

各コレクターには `CollectorContext.signal` で `AbortSignal` が渡されます。そのコレクターの予算切れ、pipeline のデッドライン超過、兄弟コレクターの失敗による決定の中止、呼び出し側の切断のいずれでも abort します。コレクターが待つ相手にそのまま渡してください — `fetch(url, { signal: context.signal })` — そうすれば外向きの処理も実際に取り消されます。

**上限を超えた決定は deny です。** `403` と `code: "collector_timeout"`、`reason.groups` は空で応答し、詳細は呼び出し側ではなく `collector_timeout` ログ行に出ます。意図的に `5xx` にはせず、「時間内に集まったぶんで判定する」こともしません — ルールが少ないことは**ポリシーが弱いこと**であり、1 つも無ければ `rule.onEmptyRuleSet = "allow"` の deployment では **allow** になるからです。そのため評価器には到達させません。バッチでは上限は決定単位なので、1 エントリの超過はそのエントリだけを deny にし、残りは通常どおり判定されます。

### リソース文字列形式 (DotNotation)

```text
"project:1"               → resourceType: "project",         resourceId: "1"
"project:1.member:2"      → resourceType: "project.member",  resourceId: "2"
"project:1.member"        → resourceType: "project.member",  resourceId: undefined
"project_member:2"        → resourceType: "project_member",  resourceId: "2"
```

文法は `segment *( "." segment )`、`segment = type [ ":" id ]` で、type / id は RFC 6749 `NQCHAR` から
`.` と `:` を除いた文字（空白・`"`・`\`・`.`・`:` を除く印字可能 ASCII）の 1 文字以上です。
`resourceType` はセグメントの type を `.` で結合したもの — 区切り文字を保持するため、ネストした type `a.b` と
`a_b` という名前のフラットな type は区別されたままになります。

それ以外は修復せず `400 invalid_request` で拒否します: 空セグメント (`a..b`)、セグメント内の 2 つ目の `:`
(`a:1:2` を `a:1` に切り詰めない)、前後および内部の空白 (`  a:1  ` を trim しない)。`resourceType` は
scope ルールが使う認可の名前空間なので、不正な入力を推測して補完するパーサーは、別のリソース向けに
発行された grant を呼び出し側に与えてしまいます。

## auth.provider との接続

auth.provider が非対称 JWT 署名 (RS256/ES256/EdDSA) を使う場合、policy-verifier の `jwksUri` をプロバイダーの JWKS エンドポイントに向ける:

```hocon
oauth.jwt {
  algorithm = "RS256"
  jwksUri = "https://auth-provider:3000/.well-known/jwks.json"
}
```

jose の `createRemoteJWKSet` により公開鍵を自動取得・キャッシュする。取得は `jwksTimeoutMs` / `jwksCooldownMs` / `jwksCacheMaxAgeMs` で上限が付く。

**JWKS URI は `https://` 必須。** そのエンドポイントが返す鍵はすべてこの deployment が受け入れるトークンを検証できる — つまりエンドポイントの同一性がトラストアンカーそのものであり、それを確立するのが TLS である。平文であれば経路上の第三者（あるいは DNS 応答を握る者）が自分の署名鍵を差し込み、検証を通るトークンを発行できる。平文 `http://` はループバックホスト（`localhost`, `127.0.0.0/8`, `[::1]`）に限って許可する — そこには攻撃者が座れる経路が存在しないためで、ローカル開発とテストのための例外である。コンテナ名や DNS 名で到達するサービス（`http://auth-provider:3000`）はループバックでは**ない**ので config パース時に拒否される。プロバイダーの前段に TLS 終端を置くか、`publicKey` / `publicKeyPath` で公開鍵を直接渡すこと。

HS256 の場合は両サービスで同じシークレットを共有:

```hocon
oauth.jwt {
  algorithm = "HS256"
  secret = ${OAUTH_JWT_SECRET}
}
```

**HS256 シークレットは鍵素材として 32 バイト（256 ビット）以上を持つこと。** 足りない値は最初のリクエストではなく起動時に拒否される。HS256 は対称鍵であり、トークンを検証する値がトークンを署名する値そのものなので、推測されることは読み取りではなく「任意の subject のトークンを発行できる」ことを意味する。RFC 7518 §3.2 はハッシュ出力幅以上の鍵を要求しており、auth.provider も同じ値に同じ下限を課している。

生成は `openssl rand -hex 32`（または `openssl rand -base64 32`）。判定は**デコード後**の素材に対して、もっとも小さく読める解釈で行う:

| 値 | 読み取り結果 | 判定 |
| --- | --- | --- |
| `openssl rand -hex 32` — 16 進 64 文字 | 32 バイト | 通る |
| `openssl rand -hex 16` — 16 進 32 文字 | 16 バイト | 拒否 |
| `openssl rand -base64 32` — 43 文字 + `=` | 32 バイト | 通る |
| ランダムな英数字 32 文字 | 24 バイト（base64 本体として読める） | 拒否 |
| 記号を含む 32 文字のパスフレーズ | 32 バイト | 通る |

見えるのは長さだけで、40 文字の英文は 40 バイトと数えられるが実際の強度ははるかに低い。シークレットは必ずランダムに生成すること。この検査は下限であって審査ではない。

下限は `secret` と下記 `previousSecrets` の全エントリに 1 つのルールとして適用される — 退役したシークレットも重複期間中は検証鍵であり、現行と同じようにトークンを発行できるからである。

### HS256 シークレットのローテーション

共有シークレットが 1 つしかない状態では、無停止でシークレットを変更する方法が存在しない。auth.provider が新しい値で署名を始めた瞬間、すでに発行済みのトークンは両サービスを同時に再起動し終えるまですべてここで弾かれる。`previousSecrets` はその同時再起動を不要にする重複期間であり、auth.provider がローテーションに使うのと同じ `kid` + `secret` + `expiresAt` の形なので、同じ 1 組の値を両側で動かすだけで済む。

1. 新しいシークレットを生成する: `openssl rand -hex 32`。
2. **まず verifier。** 旧シークレットを current に残したまま、*新しい* シークレットを previousSecrets に追加して再起動する。verifier は両方を受理する状態になるが、provider が発行するトークンは何も変わらない。

   ```hocon
   oauth.jwt {
     algorithm = "HS256"
     kid = "v0"                 # provider がまだ署名に使っているシークレット
     secret = ${OAUTH_JWT_SECRET}
     previousSecrets = [{
       kid = "v1"               # 切り替え前に先回りして受理する新シークレット
       secret = ${OAUTH_JWT_NEXT_SECRET}
       expiresAt = "2026-09-01T00:00:00Z"
     }]
   }
   ```

3. **次に provider。** 新しい `kid`/`secret` に移し、旧ペアを provider 側の `previousSecrets` に入れて再起動する。以降トークンは新シークレットで署名されて届き、verifier はすでにそれを受理できる。
4. **再び verifier。** 役割を入れ替える: 新シークレットを `kid`/`secret` にし、旧シークレットを `previousSecrets` に移して `expiresAt` にアクセストークンの TTL + バッファを設定する（auth.provider は 1 時間トークンを発行する）。再起動する。
5. その時刻を過ぎれば旧シークレットは自動的に検証に使われなくなる — 再起動は不要。エントリの削除は都合の良いときで良い。

補足:

- フィールド名は auth.provider のものだが、verifier 側では「current 以外に受理するシークレットすべて」を意味する。手順 2 で *これから来る* シークレットを先にここへ置くのはそのためで、verifier は切り替えを両側から跨ぐ必要があり、それを可能にするのがこのリストである。
- `expiresAt` はリクエストごとに評価されるため、重複期間は再起動なしに閉じる。重複期間中の旧シークレットは、それを持つ者にとって依然としてトークンを**発行**できる鍵なので、期間はトークンの寿命程度にすること（四半期単位にしない）。
- `kid` は任意であり、未設定なら従来どおり — 1 つのシークレットがすべてを検証し、トークンヘッダは読まれない。設定すると（`previousSecrets` を使うなら必須）ヘッダの照合が始まり、未設定の `kid` を持つトークンは拒否される。
- `kid` を**持たない**トークンも受理される: 設定済みのシークレット（current + previous）を順に試す。1 シークレットあたり署名検証 1 回のコストがかかるため、`previousSecrets` は **3** 件に制限されている。
- このリストは HS256 専用であり、**RS256/ES256/EdDSA では空の `previousSecrets = []` も拒否される** — 判定はキーの有無であって中身の件数ではない。これらのアルゴリズムは `jwksUri` の JWKS 経由でローテーションし（発行者が公開している鍵がすべて載っている）、このブロックは何も設定しないため、黙って無視せず起動時に拒否する。設定を非対称アルゴリズムに切り替えるときは消し忘れないこと。
- `kid` は例外で、実質 HS256 専用だが非対称アルゴリズムでは *受理された上で無視される*（これらは取得した JWKS に対して `kid` を照合する）。非対称構成の起動を壊すことはない。

## 可観測性

「なぜこのリクエストは deny されたのか」に自分の出力から答えられない認可サービスは、自分が中心にいる障害の最中に診断不能になります。以下の 2 つは `createApp` で既定有効です。運用向けの詳細はデプロイ用テンプレートの [README](templates/standalone/README.ja.md#可観測性) にあります。

### decision ログ

判定 1 件ごとに `decision` という構造化イベントを `info` で 1 行:

```json
{"msg":"decision","requestId":"6f1c…","sub":"user-42","resource":"project:7","action":"read","decision":"deny","code":"invalid_scope","deniedBy":{"ruleType":"scope","refused":["invalid_scope"]},"durationMs":0.412}
```

allow のときは `deniedBy` の代わりに `satisfiedBy` が入り、各グループを満たしたルールを示します。N 件の `POST /verify/batch` は同一 `requestId` を持つ N 行を出力します。`durationMs` はパイプラインと evaluator に費やした時間であり、HTTP の往復時間ではありません。

スイッチは `logging.level`（`LOG_LEVEL`）です — この行は `info` なので `warn` にすればストリームごと止まり、2 つ目のフラグはありません。deny は decision point にとって障害ではなく正常な結果なので `warn` には送っていません。送れば任意の呼び出し元が warn レベルのノイズを製造できてしまいます。アラートはメトリクスに、「なぜ」はログに求めてください。

**決してログに載らないもの:** 生の bearer トークン、`sub` を超えるクレーム集合、そして呼び出し元の `context` オブジェクト — 自由形式で collector にそのまま渡されるため、呼び出し側サービスのリクエストペイロードが行き着く場所そのものです。

### メトリクス

`GET /metrics`、Prometheus text exposition format:

| メトリクス | 種別 | ラベル |
|---|---|---|
| `auth_decisions_total` | counter | `decision` |
| `auth_denials_total` | counter | `code` |
| `auth_decision_duration_seconds` | histogram | `decision` |
| `http_request_duration_seconds` | histogram | `method`, `route`, `status` |
| `auth_policy_verifier_*` | 各種 | Node プロセス既定メトリクス |

`http_request_duration_seconds` は [auth.provider](https://github.com/o3co/auth.provider) と名前もラベル集合も一致するので、1 つの Prometheus job でスタックの両側を賄えます。

**すべてのラベルは有界です。** 有界でないラベルは値ごとに新しい時系列を作り出し、それは監視すべき対象を監視する仕組みそのものをメトリクスエンドポイントが落とす経路だからです。`resource` / `action` / `sub` はそもそもラベルにしていません — これらはリクエスト（ボディまたはトークン）由来で、高カーディナリティが意味を持つログ行の側に属します。`route` は Express の route パターンでマッチしないものは `route="unmatched"` に潰れ、`method` は allowlist でそれ以外は `"other"`、`code` は異なる値 32 個で打ち止めです。

**`/metrics` は `http.callerAuth` でゲートしていません。** Prometheus の scrape config が持つのは `authorization` / `basic_auth` / `oauth2` であって任意ヘッダではないため、`x-caller-token` でゲートすると標準の scraper から scrape 不能になり、*判定* を認可する資格情報を監視システムに渡す運用へ追い込むことになります。このエンドポイントが公開するのは有界ラベル上のカウントとレイテンシだけで、個々の判定に関する情報は含みません。境界となるのは bind アドレスで、既定はループバックです（#108）— scraper はホスト側に置き（同一 Kubernetes Pod のサイドカーはネットワーク名前空間を共有するので、既定のまま `127.0.0.1:3000/metrics` に到達できます）、`0.0.0.0` に bind せざるを得ない場合は `/verify` と同様にネットワーク層でポートを制限してください。

## 開発

```bash
pnpm install
pnpm -r build    # 全パッケージビルド
pnpm -r test     # 全テスト実行
```

## Docker

```bash
npx @o3co/create-auth-policy-verifier my-verifier
cd my-verifier
docker build -t my-verifier .
docker run -p 3000:3000 \
  -e HTTP_HOSTNAME=0.0.0.0 -e HTTP_CALLER_AUTH_TOKEN=<secret> \
  -e OAUTH_JWT_SECRET=$(openssl rand -hex 32) my-verifier
```

スキャフォルダーが `pnpm-lock.yaml` を生成します。イメージは
`--frozen-lockfile` でビルドするため、lockfile が無いとビルドできません。

`HTTP_HOSTNAME=0.0.0.0` はポートに到達するために必須です — 設定は既定で
loopback に bind し、コンテナの `HEALTHCHECK` はこれが未設定のとき
`unhealthy` を報告します（取り繕いません）。ポートを公開することは同時に
`HTTP_CALLER_AUTH_TOKEN` を必要にします: `/verify` は認可判断を返すため、
資格情報なしで到達可能なポートは、そこへ経路を持つ誰にでも応答します。詳細は
[`templates/standalone/README.ja.md`](templates/standalone/README.ja.md#docker)。

## 関連プロジェクト

- [auth.provider](https://github.com/o3co/auth.provider) — DID 認証対応 OAuth 2.0 プロバイダー
- [auth.proxy](https://github.com/o3co/auth.proxy) — トークン検証リバースプロキシ
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) — gRPC / ConnectRPC 向け protobuf method option 認可 interceptor (認可判定にこのサービスを呼び出す)
- [auth](https://github.com/o3co/auth) — アーキテクチャドキュメントと E2E テスト

## カバレッジ

package 単位のカバレッジは Codecov で flag ごとに分けて追跡しています:

- [core](https://codecov.io/gh/o3co/auth.policy-verifier?flag=core) — エンジンコア
- [builtins](https://codecov.io/gh/o3co/auth.policy-verifier?flag=builtins) — 組み込み collector / rule
- [server](https://codecov.io/gh/o3co/auth.policy-verifier?flag=server) — HTTP サーバ層

ローカル実行は `pnpm run test:coverage` で、各 package の `coverage/` 以下にレポートが出力されます。

## ライセンス

Apache License 2.0 — Copyright 2026 1o1 Co. Ltd.
