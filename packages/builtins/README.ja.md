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

本エンジンは `CollectorContext.requestContext` をそのまま attribute に展開するコレクターを提供しません。`requestContext` の形は利用側プロジェクトの transport/interceptor が定めるため、その解釈はプロジェクト側の責務です。必要なフィールドごとに焦点を絞った `AttributeCollector` を実装し、その中で値の型・形状を検証し、プロジェクト固有の定数キーで格納してください。詳細と具体例は [AGENTS.md — Core Vocabulary Scope](../../AGENTS.md#core-vocabulary-scope) を参照してください。

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

### AttrMatchRule

**非推奨。** 代わりに [`AttrPairEqual`](#attrpairequal) を使用してください。`AttrMatchRule` は `AttrPairEqual` を継承した薄いラッパークラスとして残されており、後方互換のため旧来の `ruleType`（`attr_match:${a}:${b}`）と旧来の `message` 文言を保持します。型 `AttrMatchRuleConfig` は `AttrPairEqualConfig` の型エイリアスです。将来のメジャーバージョンで削除されます。

```ts
new AttrMatchRule({ a: string, b: string, group?: string })
```

- `code`: `"attr_mismatch"`。
- `attrs.get(a)` と `attrs.get(b)` がいずれも非空文字列かつ等しいときに `true` を返します。それ以外はすべて `false`（fail closed）。
- 純粋な述語です。`CollectorContext` を参照しません。比較対象の値はプロジェクト側の上流 `AttributeCollector` が attrs に格納し、プロジェクト側の `RuleCollector` でこの Rule を構築します。
- `ruleType` の既定値は `"attr_match:${a}:${b}"` です。評価器は `ruleType` 内で OR、`ruleType` 間で AND を取るので、この既定値により異なる2つの比較は AND（両方必要）として扱われます。2つの比較を OR 結合したい場合（例「DID または email で一致」）は、両方の Rule に同じ `group` を指定してください。その `group` 値が `ruleType` として使われます。

## Attribute Comparison Rules

属性比較 Rule 群は 2 軸のマトリクスで構成されます: **family**（Literal または Pair）と **operator**（Equal、NotEqual、In、NotIn、Compare）。

- **Literal** Rule は、単一の名前付き属性を、コンストラクタで与えられた静的な値（または値集合）と比較します。
- **Pair** Rule は、評価時に `Attributes` から解決される 2 つの名前付き属性を互いに比較します。
- `In` / `NotIn` のバリアントは Literal family のみ提供します。集合に対する Pair 比較は有限リストへ自然に一般化できないため、`AttrPairIn` / `AttrPairNotIn` は意図的に存在しません。

| Family  | Equal              | NotEqual              | In              | NotIn              | Compare              |
| ------- | ------------------ | --------------------- | --------------- | ------------------ | -------------------- |
| Literal | `AttrLiteralEqual` | `AttrLiteralNotEqual` | `AttrLiteralIn` | `AttrLiteralNotIn` | `AttrLiteralCompare` |
| Pair    | `AttrPairEqual`    | `AttrPairNotEqual`    | —               | —                  | `AttrPairCompare`    |

### AttrLiteralEqual

```ts
new AttrLiteralEqual({ a: string, v: string | number | boolean, group?: string })
```

- `code`: `"attr_not_equal"`。
- 既定の `ruleType`: `` `attr_literal_equal:${a}:${typeof v}:${String(v)}` ``。`typeof v` セグメントは、文字列化すると同じになる異型リテラル（例: `true` と `"true"`）が同じ `ruleType` に畳み込まれるのを防ぎます。
- `attrs.get(a)` が `v` と同じ型で厳密等価のときに通過します。型の強制変換は行いません。

### AttrLiteralNotEqual

```ts
new AttrLiteralNotEqual({ a: string, v: string | number | boolean, group?: string })
```

- `code`: `"attr_equal"`。
- 既定の `ruleType`: `` `attr_literal_not_equal:${a}:${typeof v}:${String(v)}` ``。`typeof v` セグメントは異型リテラル間の衝突を防ぎます（`AttrLiteralEqual` と同じ理由）。
- `attrs.get(a)` が `v` と同じ型で厳密等価でないときに通過します。欠落または型不一致は `false`（safe-deny）を返します。

### AttrLiteralIn

```ts
new AttrLiteralIn({ a: string, values: (string | number | boolean)[], group?: string })
```

- `code`: `"attr_not_in_set"`。
- 既定の `ruleType`: `` `attr_literal_in:${a}:${type}:${count}:${hashPrefix}` `` — `hashPrefix` は `values` をソートして文字列化した内容に対する SHA-256 の先頭 8 桁（例: `attr_literal_in:role:string:2:a1b2c3d4`）。同じ `a` と内容上等価な `values`（順序非依存）を持つ 2 つのインスタンスは同じ `ruleType` を持ち、評価器で OR 結合されます。
- `values` は非空かつ同種の配列（`string[]`、`number[]`、`boolean[]` のいずれか）でなければなりません。`attrs.get(a)` が集合に含まれるときに通過します。

### AttrLiteralNotIn

```ts
new AttrLiteralNotIn({ a: string, values: (string | number | boolean)[], group?: string })
```

- `code`: `"attr_in_set"`。
- 既定の `ruleType`: `` `attr_literal_not_in:${a}:${type}:${count}:${hashPrefix}` `` — `AttrLiteralIn` と同じ安定ハッシュ方式。
- `values` は非空かつ同種の配列。`attrs.get(a)` が集合に含まれないときに通過します。

### AttrLiteralCompare

```ts
new AttrLiteralCompare({ a: string, op: "lt" | "le" | "gt" | "ge", v: number, group?: string })
```

- `code`: `"attr_compare_violated"`。
- 既定の `ruleType`: `` `attr_literal_compare:${a}:${op}:${String(v)}` ``。
- `attrs.get(a)` が数値であり `a op v` を満たすときに通過します。`v` が NaN の場合はコンストラクタ時点で拒否されます。属性側が NaN の場合は常に `false` を返します。

### AttrPairEqual

```ts
new AttrPairEqual({ a: string, b: string, group?: string })
```

- `code`: `"attr_mismatch"`。
- 既定の `ruleType`: `` `attr_pair_equal:${a}:${b}` ``。
- `attrs.get(a)` と `attrs.get(b)` がいずれも非空文字列かつ厳密等価のときに通過します。非推奨となった `AttrMatchRule` の後継です。

### AttrPairNotEqual

```ts
new AttrPairNotEqual({ a: string, b: string, group?: string })
```

- `code`: `"attr_match"`。
- 既定の `ruleType`: `` `attr_pair_not_equal:${a}:${b}` ``。
- `attrs.get(a)` と `attrs.get(b)` がいずれも非空文字列かつ厳密等価でないときに通過します。欠落・空文字列・非文字列はすべて `false`（safe-deny）を返します。

### AttrPairCompare

```ts
new AttrPairCompare({ a: string, op: "lt" | "le" | "gt" | "ge", b: string, group?: string })
```

- `code`: `"attr_compare_violated"`。
- 既定の `ruleType`: `` `attr_pair_compare:${a}:${op}:${b}` ``。
- `attrs.get(a)` と `attrs.get(b)` がいずれも数値で `a op b` を満たすときに通過します。どちらかが NaN の場合は `false` を返します（JS の比較セマンティクス）。

### グルーピング: 既定は AND、OR にするには `group` を指定

属性比較 Rule はすべて、上記 `AttrMatchRule` と同じグルーピング規則に従います。既定では各 Rule の `ruleType` は識別用パラメータから導出されるため、異なる要件は評価器によって AND 結合されます。2 つの Rule に同じ `group` 文字列を渡すと、両者は同じ `ruleType` を持つようになり、評価器は OR 結合します（どちらか一方が成立すれば要件を満たす）。

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
