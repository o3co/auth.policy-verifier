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
  │  1. JWT 検証 (HS256 / RS256 / ES256 / EdDSA)     │
  │                                                   │
  │  2. AttributeCollectors (並列)                    │
  │     ├─ PayloadScopeCollector → JWT からスコープ   │
  │     ├─ PayloadSubjectIdCollector → サブジェクトID  │
  │     └─ (カスタム Collector...)                    │
  │                                                   │
  │  3. RuleCollectors (並列)                         │
  │     ├─ ResourceActionScopeRuleCollector            │
  │     │   → HasScope("read:project")                │
  │     └─ (カスタム RuleCollector...)                │
  │                                                   │
  │  4. 評価                                          │
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

## 特徴

- **Collector パターン** — 属性とルールはコンポーザブルな Collector で収集。静的なポリシーファイルではない。任意の属性ソース（DB, 外部 API, JWT クレーム）向けにカスタム Collector を追加可能。
- **boolean ではなく decision 契約** — リクエストは `(subject, resource, action, context)`、応答は各ルールグループとその結果を並べた構造化 `reason` を必ず伴う。「なぜ deny されたか」をパイプラインの再実行なしに答えられる。`POST /verify/batch` は複数リソースを 1 往復で判定する。
- **JWT 検証アルゴリズム設定可能** — HS256（共有シークレット）、RS256/ES256/EdDSA（JWKS URI または公開鍵直接指定）。[auth.provider](https://github.com/o3co/auth.provider) の JWT 設定と対称設計。
- **RFC 9068 §4 のトークン検証** — 署名だけでなく `iss` / `aud` / `typ` ヘッダも検証する。同じ鍵で署名された `id_token` / refresh token / logout token や、他サービス向けに発行されたトークンは拒否される。`mode = "verify"`（デフォルト）のとき `issuer` と `audience` は必須。
- **JWKS サポート** — `jwksUri` を auth.provider の `https://.../.well-known/jwks.json` に向ければ鍵ローテーションに自動対応。エンドポイントは TLS 必須（ローカル開発向けにループバックのみ例外）。取得はタイムアウト / クールダウン / キャッシュ期間で必ず上限が付き、プロバイダー障害が判定パスを止めない。
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
OAUTH_JWT_SECRET=your-secret \
  OAUTH_JWT_ISSUER=https://issuer.example.com \
  OAUTH_JWT_AUDIENCE=https://api.example.com \
  pnpm start
```

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

- **core** — 型定義、`evaluate()`、`AttributePipeline`、`RulePipeline`、Module 基盤。ランタイム依存なし。
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
    secret = ${?OAUTH_JWT_SECRET}           # HS256
    jwksUri = ${?OAUTH_JWT_JWKS_URI}        # RS256/ES256/EdDSA — https 必須、例: https://auth-provider/.well-known/jwks.json
    jwksTimeoutMs = 5000                     # JWKS 取得の上限 — 打ち切り時間
    jwksCooldownMs = 30000                   # 再取得の最小間隔
    jwksCacheMaxAgeMs = 600000               # 取得済み JWKS のキャッシュ期間
    publicKey = ${?OAUTH_JWT_PUBLIC_KEY}     # RS256/ES256/EdDSA — PEM 文字列
    publicKeyPath = ${?OAUTH_JWT_PUBLIC_KEY_PATH}  # またはファイルパス
    issuer = ${?OAUTH_JWT_ISSUER}           # mode = "verify" のとき必須 — RFC 9068 §4 iss
    audience = ${?OAUTH_JWT_AUDIENCE}       # mode = "verify" のとき必須 — RFC 9068 §4 aud
    tokenType = "at+jwt"                     # 受け入れる typ ヘッダ
    tokenType = ${?OAUTH_JWT_TOKEN_TYPE}
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
}
```

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
docker run -e OAUTH_JWT_SECRET=secret my-verifier
```

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
