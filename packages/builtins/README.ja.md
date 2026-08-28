# @o3co/auth.policy-verifier.builtins

auth.policy-verifier 向けの組み込み attribute collector、rule collector、および resource parser です。

**Runtime:** `BigInt` と `Map.groupBy` をサポートするサーバー／エッジ JavaScript ランタイムが対象です — Node.js 22+（`engines.node` で宣言しており、古い Node ではインストール時にブロックされます）、Cloudflare Workers、Vercel Edge、Deno、Bun。ブラウザは設計上対象外です（認可判定はサーバー側で enforcement する必要があるため）。同梱の `server` パッケージは引き続き Node 専用です。

## インストール

```bash
npm install @o3co/auth.policy-verifier.builtins
```

## Attribute Collectors

すべての collector は `AttributeCollector` を実装しています。

| 名前 | 読み取り元 | 出力 | コンストラクタ引数 |
| --- | --- | --- | --- |
| `PayloadScopeCollector` | `subject.scope`（スペース区切り文字列） | `ATTR_SCOPES: string[]` | なし |
| `PayloadSubjectIdCollector` | `subject.sub`、`subject.azp` | `ATTR_USER_ID`、`ATTR_CLIENT_ID` | なし |
| `StaticPermissionCollector` | — | `ATTR_PERMISSIONS: string[]` | `{ permissions: string[] }` |
| `StaticRoleCollector` | — | `ATTR_ROLES: Role[]` | `{ roles: Role[] }` |
| `RequestContextAttributeCollector` | `requestContext` の宣言済みフィールド | 運用者が決めたキー | `{ attributes: Mapping[] }` |

`StaticPermissionCollector` と `StaticRoleCollector` は、リクエストのコンテキストに関わらず、コンストラクタに渡した値を常に出力します。

### RequestContextAttributeCollector

`CollectorContext.requestContext` の宣言済みフィールドを attribute に昇格させます:

```hocon
{ collector = "RequestContextAttributeCollector"
  attributes = [
    { from = "tenant.id", to = "tenantId" }     # dot path。`to` の既定値は `from`
    { from = "groups", type = "string[]" }
  ] }
```

各マッピングは `{ from: string; to?: string; type?: "string" | "number" | "boolean" | "string[]" }` で、`type` の既定は `"string"` です。マッピング定義が不正ならコンストラクタで throw しますが、*値* が使えない場合は throw しません — `requestContext` は呼び出し側が渡すリクエストデータなので、欠落・空文字・宣言した型に合わない値は単に昇格されません。

この宣言が信頼境界です — [docs/extending.ja.md](../../docs/extending.ja.md#信頼境界-requestcontext-は呼び出し側のもの) が説明する境界の、既製の守り方がこのコレクターです。`requestContext` は自由形式かつ未検証なので、**宣言していないフィールドは attribute になりません**。dot path は own property のみを辿るため `constructor.name` のような指定は何も読みません。このコレクター自身は語彙を持ち込みません — フィールド名もキー名も運用者が決めるため、[AGENTS.md — Core Vocabulary Scope](../../AGENTS.md#core-vocabulary-scope) の方針を崩さずに実用的なものを提供できます。read-check-write を超える処理（値の導出、外部ストア参照など）が必要な場合は、同節が説明するプロジェクト側の `AttributeCollector` を書いてください。

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
new HasScope(scope: string, options?: { allowBareScopeRewrite?: boolean })
```

- `ruleType`: `"scope"`、`code`: `"invalid_scope"`
- `ATTR_SCOPES` を確認します。
- 比較は**大文字・小文字を区別する完全一致**です。OAuth 2.0 の scope 値は大文字・小文字を区別する不透明な文字列であるため（[RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3)）、`read:PROJECT` は `read:project` を満たしません。
- `:` を 2 つ以上含む scope はそれ自体が 1 つの値であり、2 つ目の `:` 以降が切り捨てられることはありません。`read:project:restricted` は `read:project` を満たさず（意図的に絞り込まれた grant が広い方へ吸収されてはならない）、`read:project` も `read:project:restricted` を満たしません。
- `allowBareScopeRewrite`（既定 `false`）を有効にすると、プレフィックスなしの scope `"resource"` を、そのままの値に加えて `"read:resource"` としても扱います。書き換え対象は `:` を **1 つも含まない** scope のみで、`"project:restricted"` は書き換えません（どのセグメントが action かは判別不能であり、推測は過剰付与になるため）。issuer がプレフィックスなしのリソース名を発行する場合以外は無効のままにしてください。
- `ATTR_SCOPES` 内の文字列以外の要素は、一致もせず例外も投げません。

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
- 既定の `ruleType`: `` `attr_literal_in:${a}:${type}:${count}:${hashPrefix}` `` — `count` は重複除去後の要素数、`hashPrefix` は重複除去かつソート済みの `values` を文字列化した内容に対する FNV-1a 64-bit ハッシュの 16 桁 16 進表記です。ハッシュは非暗号学的ですが、64-bit 幅により現実的な policy サイズで偶発的・意図的な衝突はいずれもほぼ起きません。`node:*` 依存はなく、対象とするサーバー／エッジランタイム（冒頭「Runtime」参照）でロードできます。同じ `a` と内容上等価な `values`（順序・重複を無視）を持つ 2 つのインスタンスは同じ `ruleType` を持ち、評価器で OR 結合されます。
- `values` は非空かつ同種の配列（`string[]`、`number[]`、`boolean[]` のいずれか）でなければなりません。`attrs.get(a)` が集合に含まれるときに通過します。`values` 内の重複要素は Rule の挙動に影響しません（内部では `Set` として扱われます）。

### AttrLiteralNotIn

```ts
new AttrLiteralNotIn({ a: string, values: (string | number | boolean)[], group?: string })
```

- `code`: `"attr_in_set"`。
- 既定の `ruleType`: `` `attr_literal_not_in:${a}:${type}:${count}:${hashPrefix}` `` — `AttrLiteralIn` と同じ、重複除去済みの安定ハッシュ方式。
- `values` は非空かつ同種の配列。`attrs.get(a)` が集合に含まれないときに通過します。`values` 内の重複要素は Rule の挙動に影響しません。

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

`ResourceActionPermissionRuleCollector` にコンストラクタ引数はありません。
`ResourceActionScopeRuleCollector` は `{ scopeless?: "deny" | "skip", allowBareScopeRewrite?: boolean }` を受け取ります。

- `scopeless`（既定 `"deny"`）: 既定ではリクエストごとに必ず `HasScope` ルールを生成するため、`scope` claim を持たない
  トークンはこのルールに落ちます。`"skip"` は scopeless トークンに対してルールを生成しませんが、ルールが 1 つも集まらない
  リクエストは deny されるため、別のルールグループが認可を担うパイプラインでのみ使ってください。
- `allowBareScopeRewrite`（既定 `false`）: [`HasScope`](#hasscope) へそのまま渡されます。issuer が `{action}:{resourceType}`
  形式（`read:project`）ではなくプレフィックスなしのリソース名（`project`）を発行する場合にのみ `true` にしてください。

## Resource Parser

### DotNotationResourceParser

ドット記法の文字列を `Resource` へパースします。

```ts
new DotNotationResourceParser()
```

文法:

```text
resource = segment *( "." segment )
segment  = type [ ":" id ]
type     = 1*tchar
id       = 1*tchar
tchar    = %x21 / %x23-2D / %x2F-39 / %x3B-5B / %x5D-7E
           ; RFC 6749 NQCHAR から "." と ":" を除いたもの
           ; すなわち、空白・`"`・`\`・`.`・`:` を除く印字可能 ASCII
```

例: `"foo.bar:123"` → `{ raw: "foo.bar:123", resourceType: "foo.bar", resourceId: "123" }`

- セグメントは `.` で分割されます。各セグメントには `:id` を含めることができます。
- `resourceType` はセグメントの type を `.` で結合した文字列です。区切り文字は書き換えず、そのまま保持されます。
- `resourceId` は最後のセグメントの id です（存在する場合）。
- `raw` は入力そのままです。

文法に合わない入力は `ResourceParseError`（`@o3co/auth.policy-verifier.core`）を送出します。パーサーが入力を
修復することはありません。サーバーはそのリクエストを decision ではなく `400 invalid_request` として返します。
拒否される例:

| 入力 | 理由 |
| --- | --- |
| `""`, `a..b`, `.a`, `a.` | 空セグメント — すべてのセグメントに type が必要 |
| `a:`, `:1` | type または id が空 |
| `a:1:2` | セグメント内に `:` が 2 個以上 — 末尾を切り捨てず拒否する |
| `  a:1  `, `a : 1` | 空白 — trim せず拒否する |
| `プロジェクト`, `a"b`, `a\b` | OAuth scope 値が持てない文字 |

`resourceType` は認可の名前空間です。`ResourceActionScopeRuleCollector` はこれを
`{action}:{resourceType}` scope に変換し、その scope が付与されていることを要求します。つまり同じ type に
パースされる 2 つの異なるリソースは同一に認可されてしまうため、そうならないように文法を設計しています。
`.` を区切り文字として予約することで、ネストした type `a.b` と `a_b` という名前のフラットな type が
区別されます（以前はどちらも `a_b` でした）。これは [`HasScope`](#hasscope) が scope 値に対して適用しているのと
同じ原則です — 書かれたものをそのまま比較し、意図を正規化して推測しない。

`.` や `:`、あるいは許可集合外の文字を必要とする id は、呼び出し側でエンコードする（percent-encoding は
この文法をそのまま通ります）か、その構文向けに書かれた `ResourceParser` で扱ってください。

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
| `attributeCollector` | `"RequestContextAttributeCollector"` | `(config) => new RequestContextAttributeCollector(config)` |
| `ruleCollector` | `"ResourceActionScopeRuleCollector"` | `(config) => new ResourceActionScopeRuleCollector(config)` |
| `ruleCollector` | `"ResourceActionPermissionRuleCollector"` | `() => new ResourceActionPermissionRuleCollector()` |
| `resourceParser` | `"DotNotationResourceParser"` | `() => new DotNotationResourceParser()` |

## 関連

- [拡張ガイド (`docs/extending.ja.md`)](../../docs/extending.ja.md) — カスタム `Rule` / `AttributeCollector` の書き方と、`builtins` が基本セットとして位置づけられている理由
- [`@o3co/auth.policy-verifier.core`](../core/README.ja.md) — コアインターフェースと attribute 定数
- [auth.policy-verifier ルート README](../../README.ja.md) — 完全なセットアップと設定のリファレンス
