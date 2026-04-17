# @o3co/auth.policy-verifier.builtins

auth.policy-verifier 向けの組み込み attribute collector、rule collector、および resource parser です。

## インストール

```bash
npm install @o3co/auth.policy-verifier.builtins
```

## Attribute Collectors

すべての collector は `AttributeCollector` を実装しています。

| 名前 | 読み取り元 | 出力 | コンストラクタ引数 |
| --- | --- | --- | --- |
| `PayloadScopeCollector` | `payload.scope`（スペース区切り文字列） | `ATTR_SCOPES: string[]` | なし |
| `PayloadSubjectIdCollector` | `payload.sub`、`payload.azp` | `ATTR_USER_ID`、`ATTR_CLIENT_ID` | なし |
| `StaticPermissionCollector` | — | `ATTR_PERMISSIONS: string[]` | `{ permissions: string[] }` |
| `StaticRoleCollector` | — | `ATTR_ROLES: Role[]` | `{ roles: Role[] }` |

`StaticPermissionCollector` と `StaticRoleCollector` は、リクエストのコンテキストに関わらず、コンストラクタに渡した値を常に出力します。

### `requestContext` 向けの組み込みコレクターは提供しない

本エンジンは `CollectorContext.requestContext` をそのまま attribute に展開するコレクターを提供しません。`requestContext` の形は利用側プロジェクトの transport/interceptor が定めるため、その解釈はプロジェクト側の責務です。必要なフィールドごとに焦点を絞った `AttributeCollector` を実装し、その中で値の型・形状を検証し、プロジェクト固有の定数キーで格納してください。詳細と具体例はリポジトリルートの `AGENTS.md` の Core Vocabulary Scope セクションを参照してください。

## Rules

### HasPermission

```ts
new HasPermission(permission: string)
```

- `ruleType`: `"permission"`、`code`: `"no_permission"`
- `ATTR_PERMISSIONS`（直接）と `ATTR_ROLES[].permissions`（ロール経由）を確認します。
- ワイルドカードマッチ（大文字・小文字を区別しない）:
  - `"*"` はすべての permission に一致。
  - `"foo*"` はプレフィックスが `foo` の permission に一致。
  - `"*bar"` はサフィックスが `bar` の permission に一致。
  - `"foo*bar"` は `foo` で始まり `bar` で終わる permission に一致。

### HasScope

```ts
new HasScope(scope: string)
```

- `ruleType`: `"scope"`、`code`: `"invalid_scope"`
- `ATTR_SCOPES` を確認します。
- `ATTR_SCOPES` 内のプレフィックスなし scope 文字列（例: `"resource"`）は、比較前に `"read:resource"` へ正規化されます。
- 正規化後に大文字・小文字を区別しない完全一致で比較します。

## Rule Collectors

| 名前 | 導出する permission / scope | 返り値 |
| --- | --- | --- |
| `ResourceActionPermissionRuleCollector` | `"<resource.raw>.perm:<action>"` | `[HasPermission(...)]` |
| `ResourceActionScopeRuleCollector` | `"<action>:<resource.resourceType>"` | `[HasScope(...)]` |

どちらもコンストラクタ引数はありません。

## Resource Parser

### DotNotationResourceParser

ドット記法の文字列を `Resource` へパースします。

```ts
new DotNotationResourceParser()
```

入力形式: `"<type>[:<id>].<type>[:<id>]..."`

例: `"foo.bar:123"` → `{ raw: "foo.bar:123", resourceType: "foo_bar", resourceId: "123" }`

- セグメントは `.` で分割されます。各セグメントには `:id` を含めることができます。
- `resourceType` はセグメントの type を `_` で結合した文字列です。
- `resourceId` は最後のセグメントの id です（存在する場合）。

## builtinCollectorsModule

`builtinCollectorsModule` は `Module`（name: `"builtin-collectors"`）です。組み込みの実装をすべてそれぞれのレジストリに登録します。

```ts
import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
```

| レジストリ | 名前 | ファクトリ |
| --- | --- | --- |
| `attributeCollector` | `"PayloadScopeCollector"` | `() => new PayloadScopeCollector()` |
| `attributeCollector` | `"PayloadSubjectIdCollector"` | `() => new PayloadSubjectIdCollector()` |
| `attributeCollector` | `"StaticPermissionCollector"` | `(config) => new StaticPermissionCollector(config)` |
| `attributeCollector` | `"StaticRoleCollector"` | `(config) => new StaticRoleCollector(config)` |
| `ruleCollector` | `"ResourceActionScopeRuleCollector"` | `() => new ResourceActionScopeRuleCollector()` |
| `ruleCollector` | `"ResourceActionPermissionRuleCollector"` | `() => new ResourceActionPermissionRuleCollector()` |
| `resourceParser` | `"DotNotationResourceParser"` | `() => new DotNotationResourceParser()` |

## 関連

- [`@o3co/auth.policy-verifier.core`](../core/README.md) — コアインターフェースと attribute 定数
- [auth.policy-verifier ルート README](../../README.md) — 完全なセットアップと設定のリファレンス
