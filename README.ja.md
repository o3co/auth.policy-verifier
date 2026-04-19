# auth.policy-verifier

[![CI](https://github.com/o3co/auth.policy-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.policy-verifier/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/auth.policy-verifier.core)](https://www.npmjs.com/package/@o3co/auth.policy-verifier.core)
[![codecov](https://codecov.io/gh/o3co/auth.policy-verifier/graph/badge.svg)](https://codecov.io/gh/o3co/auth.policy-verifier)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

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
  │                                                   │
  │  → 200 {"decision": "allow"}                      │
  │  → 403 {"decision": "deny", "code": "..."}       │
  └──────────────────────────────────────────────────┘
```

## 特徴

- **Collector パターン** — 属性とルールはコンポーザブルな Collector で収集。静的なポリシーファイルではない。任意の属性ソース（DB, 外部 API, JWT クレーム）向けにカスタム Collector を追加可能。
- **JWT 検証アルゴリズム設定可能** — HS256（共有シークレット）、RS256/ES256/EdDSA（JWKS URI または公開鍵直接指定）。[auth.provider](https://github.com/o3co/auth.provider) の JWT 設定と対称設計。
- **JWKS サポート** — `jwksUri` を auth.provider の `/.well-known/jwks.json` に向ければ鍵ローテーションに自動対応。
- **プラグイン可能なアーキテクチャ** — Module システムでカスタム Collector、ルール、リソースパーサーをファクトリ経由で登録。
- **DSL ロックインなし** — 認可ロジックは TypeScript。Rego も Cedar ポリシー言語も不要。スケールアウトが必要になれば [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors) 経由で OPA や Cedar に差し替え可能 — interceptor がバックエンドを抽象化する。

## いつ選ぶか

- ポリシーを書くのは開発者で、DSL を学習したくない → **これ**
- ポリシーを非開発者が編集する、または形式検証が必要 → **[Cedar](https://www.cedarpolicy.com/)**
- 組織全体のポリシー基盤として広範な built-in operator 群が必要 → **[OPA](https://www.openpolicyagent.org/)**

## Quick Start

```bash
npx create-o3co-policy-verifier my-policy-verifier
cd my-policy-verifier
pnpm install
OAUTH_JWT_SECRET=your-secret pnpm start
```

```bash
curl -X POST http://localhost:3000/verify \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"resource": "project:1", "action": "read"}'
```

```json
{"decision": "allow"}
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
| [`create-app`](create-app/) | `create-o3co-policy-verifier` | CLI スキャフォルダー |

## 評価ロジック

ルールは `ruleType`（例: "scope", "permission"）でグループ化:

- **グループ内:** OR — 1つでも通ればそのグループは通過
- **グループ間:** AND — 全グループが通過する必要あり

ルールなし → allow。RuleCollector が未設定なら全リクエストが許可される。

### 組み込みルール

| ルール | 生成元 | マッチ条件 |
| --- | --- | --- |
| `HasScope("read:project")` | `ResourceActionScopeRuleCollector` | JWT の `scope` クレームに `read:project` が含まれる |
| `HasPermission("project:1.perm:read")` | `ResourceActionPermissionRuleCollector` | ユーザーの permissions/roles にマッチするパターンが含まれる（`*` ワイルドカード対応） |

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
    jwksUri = ${?OAUTH_JWT_JWKS_URI}        # RS256/ES256/EdDSA — 例: http://auth-provider/.well-known/jwks.json
    publicKey = ${?OAUTH_JWT_PUBLIC_KEY}     # RS256/ES256/EdDSA — PEM 文字列
    publicKeyPath = ${?OAUTH_JWT_PUBLIC_KEY_PATH}  # またはファイルパス
    validate = true
    validate = ${?OAUTH_JWT_VALIDATE}
  }
}

attribute {
  collectors = [
    { collector = "PayloadScopeCollector" }
    { collector = "PayloadSubjectIdCollector" }
  ]
}

rule {
  collectors = [
    { collector = "ResourceActionScopeRuleCollector" }
  ]
}

resource {
  parser = DotNotationResourceParser
}
```

### リソース文字列形式 (DotNotation)

```text
"project:1"               → resourceType: "project",         resourceId: "1"
"project:1.member:2"      → resourceType: "project_member",  resourceId: "2"
"project:1.member"        → resourceType: "project_member",  resourceId: undefined
```

## auth.provider との接続

auth.provider が非対称 JWT 署名 (RS256/ES256/EdDSA) を使う場合、policy-verifier の `jwksUri` をプロバイダーの JWKS エンドポイントに向ける:

```hocon
oauth.jwt {
  algorithm = "RS256"
  jwksUri = "http://auth-provider:3000/.well-known/jwks.json"
}
```

jose の `createRemoteJWKSet` により公開鍵を自動取得・キャッシュする。

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
npx create-o3co-policy-verifier my-verifier
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
