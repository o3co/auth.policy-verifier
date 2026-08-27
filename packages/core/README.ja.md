# @o3co/auth.policy-verifier.core

auth.policy-verifier の型定義・評価エンジン・モジュール基盤。コレクター、ルール、モジュールが実装すべきインターフェースを定義するパッケージです。

**Runtime:** `Map.groupBy` をサポートするサーバー／エッジ JavaScript ランタイムが対象です — Node.js 22+（`engines.node` で宣言しており、古い Node ではインストール時にブロックされます）、Cloudflare Workers、Vercel Edge、Deno、Bun。ブラウザは設計上対象外です（認可判定はサーバー側で enforcement する必要があるため）。同梱の `server` パッケージは引き続き Node 専用です。

## インストール

```bash
npm install @o3co/auth.policy-verifier.core
```

## パブリック API

### evaluate

```typescript
interface EvaluateOptions {
  /** Decision for an empty rule set. Defaults to "deny". */
  onEmptyRuleSet?: "deny" | "allow"
}

function evaluate(attrs: Attributes, rules: Rule[], options?: EvaluateOptions): Decision
```

収集した属性をルールセットに対して評価します。ルールは `ruleType` でグループ化され、グループ内はいずれかのルールが通れば満足（OR）、すべてのグループが満たされた場合に許可（グループ間 AND）となります。戻り値は `{ decision: "allow"; reason }` または `{ decision: "deny"; code: string; message: string; reason }` です。

**ルールが 1 つも集まらなかった場合は deny** (`code: "no_applicable_rule"`) です。どのルールも適用されなかったリクエストは認可されていないためです。第 3 引数に `{ onEmptyRuleSet: "allow" }` を渡すと、この既定を deployment 単位で opt-out できます。

すべての決定は構造化された `reason` を伴います。`reason.groups` は評価順に各ルールグループを並べ、`passed` と、
そのグループで実際に走ったルールを評価順に列挙した `evaluated` を持ちます。失敗グループは全代替ルールを
走らせているのでそのすべてが並びます。通過グループは OR なので最初に通ったルールで打ち切り、`evaluated` には
先に試して失敗した代替ルールに続いてそのルールが入り、決め手となったそのルールは `satisfiedBy`
（通過グループにのみ存在）で明示されます。最初に失敗したグループ以降も評価します — 途中で打ち切ると
「残りも失敗したのか」に答えられないためです。deny の `code` / `message` は従来どおり最初に失敗した
グループから取ります。

**ルールが 1 つも集まらなかった場合は deny** (`code: "no_applicable_rule"`) です。どのルールも適用されなかったリクエストは認可されていないためです。第 3 引数に `{ onEmptyRuleSet: "allow" }` を渡すと、この既定を deployment 単位で opt-out できます。

### AttributePipeline

```typescript
class AttributePipeline {
  constructor(collectors: AttributeCollector[])
  collect(context: CollectorContext): Promise<Attributes>
}
```

すべてのコレクターを並列実行し、結果をマージします。配列値は結合され、それ以外の型は後書きが優先されます。

### RulePipeline

```typescript
class RulePipeline {
  constructor(collectors: RuleCollector[])
  collect(context: CollectorContext): Promise<Rule[]>
}
```

すべてのコレクターを並列実行し、結果を単一の配列にフラット化します。

### Registry\<T\>

```typescript
class Registry<T> {
  register(name: string, instance: T): void
  get(name: string): T
  has(name: string): boolean
  entries(): [string, T][]
}
```

名前付きレジストリです。`register` は重複名を渡すと例外をスローし、`get` は名前が見つからない場合に例外をスローします。

### Module / ModuleContext

```typescript
interface Module {
  name: string
  init(context: ModuleContext): Promise<void>
}

interface ModuleContext {
  pathResolver: PathResolver
  config: Record<string, unknown>
  attributeCollectorRegistry: Registry<AttributeCollectorFactory>
  ruleCollectorRegistry: Registry<RuleCollectorFactory>
  resourceParserRegistry: Registry<ResourceParserFactory>
  keyResolverRegistry: Registry<KeyResolverFactory>
}
```

モジュールは `init` 内でコレクター・パーサー・鍵リゾルバーのファクトリーをレジストリに登録します。設定値は `config` を通じて渡されます。

### 型一覧

| 型 | 説明 |
| --- | --- |
| `Resource` | `{ raw: string; resourceType: string; resourceId?: string }` — パース済みリソース |
| `ResourceParser` | `parse(raw: string): Resource` — 生のリソース文字列を `Resource` に変換する。パース対象の構文に合わない文字列には `ResourceParseError` を送出する |
| `ResourceParseError` | `raw`（拒否した文字列）と `detail`（理由）を持つ `Error` サブクラス。サーバーエラーではなく**リクエスト**エラーであり、トランスポート層は 400 系で応答する。クラスとして export されるため `instanceof` で絞り込める |
| `CollectorContext` | 各コレクターに渡される入力: `payload`、`resource`、`action`、省略可能な `headers` と `requestContext` |
| `Attributes` | `Map<string, unknown>` — サブジェクト属性のバッグ |
| `AttributeCollector` | `collect(context: CollectorContext): Promise<Attributes>` |
| `Rule` | `{ ruleType: string; code: string; message: string; verify(attrs: Attributes): boolean }` |
| `RuleCollector` | `collect(context: CollectorContext): Promise<Rule[]>` |
| `Decision` | `{ decision: "allow"; reason: DecisionReason } \| { decision: "deny"; code: string; message: string; reason: DecisionReason }` |
| `DecisionReason` | `{ groups: RuleGroupOutcome[] }` |
| `RuleGroupOutcome` | `{ ruleType: string; passed: true; evaluated: RuleOutcome[]; satisfiedBy: RuleOutcome } \| { ruleType: string; passed: false; evaluated: RuleOutcome[] }` — `evaluated` は実際に走ったルールを評価順に列挙し、`satisfiedBy` は通過グループを満たしたルールを指す |
| `RuleOutcome` | `{ code: string; message: string; passed: boolean }` |
| `Role` | `{ name: string; permissions: string[] }` |
| `VerifierPayload` | デコード済み JWT クレーム: `sub`、`azp`、`scope`、`iss`、`aud`、`exp`、`iat`、`token`、`tokenType`、および任意の追加クレーム |
| `PathResolver` | `(specifier: string) => string` — モジュール相対パスを解決する |
| `AttributeCollectorFactory` | config から `AttributeCollector` を生成するファクトリー関数 |
| `RuleCollectorFactory` | config から `RuleCollector` を生成するファクトリー関数 |
| `ResourceParserFactory` | config から `ResourceParser` を生成するファクトリー関数 |
| `KeyResolver` | `{ key: unknown; algorithms: string[] }` — 抽象的な JWT 鍵マテリアル。具体的な `key` の型は利用する JWT ライブラリ（デフォルト server では jose）側が決める |
| `KeyResolverFactory` | アルゴリズムごとに `KeyResolver` を生成するファクトリー関数 `(config: any) => Promise<KeyResolver>` |

### 定数

`ATTR_*` 定数は OAuth 2.0 / OIDC および RBAC の標準語彙に限定しています。これらはこのエンジンを利用するすべてのサービスが共通して扱う概念（JWT クレーム、OAuth スコープ、RBAC のロール・パーミッション）です。業務ドメイン固有の属性キーは core ではなく、利用側サービスに属します。利用側は独自のキー定数を定義し、同じ `Attributes` マップを介して読み書きします。

| 定数 | 値 | 説明 |
| --- | --- | --- |
| `ATTR_SCOPES` | `"scopes"` | OAuth スコープの属性キー |
| `ATTR_PERMISSIONS` | `"permissions"` | 明示的なパーミッションの属性キー |
| `ATTR_ROLES` | `"roles"` | ロールの属性キー |
| `ATTR_USER_ID` | `"userId"` | サブジェクトユーザー ID（JWT `sub`）の属性キー |
| `ATTR_CLIENT_ID` | `"clientId"` | クライアント ID（JWT `azp`）の属性キー |

## 使い方

```typescript
import { AttributePipeline, RulePipeline, evaluate } from '@o3co/auth.policy-verifier.core'
import {
  PayloadScopeCollector,
  ResourceActionScopeRuleCollector,
  DotNotationResourceParser,
} from '@o3co/auth.policy-verifier.builtins'

const parser = new DotNotationResourceParser()
const resource = parser.parse('project:1')
const context = { payload: decodedJwt, resource, action: 'read' }

const attrs = await new AttributePipeline([new PayloadScopeCollector()]).collect(context)
const rules = await new RulePipeline([new ResourceActionScopeRuleCollector()]).collect(context)
const decision = evaluate(attrs, rules)
```

## カスタムコレクターの書き方

`AttributeCollector`（または `RuleCollector`）を実装し、`Module` でラップして、`ModuleContext` 経由でファクトリーを登録します。

```typescript
// collectors/MyRoleCollector.mts
import type { Attributes, AttributeCollector, CollectorContext } from '@o3co/auth.policy-verifier.core'
import { ATTR_ROLES } from '@o3co/auth.policy-verifier.core'

export class MyRoleCollector implements AttributeCollector {
  constructor(private config: { endpointUrl: string }) {}

  async collect(context: CollectorContext): Promise<Attributes> {
    // 自分の API からロールを取得する
    return new Map([[ATTR_ROLES, roles]])
  }
}
```

```typescript
// modules/custom.mts
import type { Module } from '@o3co/auth.policy-verifier.core'
import { MyRoleCollector } from '../collectors/MyRoleCollector.mjs'

export const customModule: Module = {
  name: 'custom',
  async init(context) {
    context.attributeCollectorRegistry.register(
      'MyRoleCollector',
      (config) => new MyRoleCollector(config),
    )
  },
}
```

`customModule` をスタンドアロンエントリーポイントの `createApp` に渡してください。完全なセットアップ例はルートの README を参照してください。

カスタム `Rule` の書き方、`ruleType` のグルーピング規約、独自ロジックを書くべきときと [`@o3co/auth.policy-verifier.builtins`](../builtins/README.ja.md) を使うべきときの判断基準などを含む完全な拡張ガイドは [`docs/extending.ja.md`](../../docs/extending.ja.md) を参照してください。

## 関連

- [ルート README](../../README.ja.md) — セットアップ全体、設定、サーバー利用方法
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.ja.md) — 組み込みコレクター、ルール、リソースパーサー
- [`@o3co/auth.policy-verifier.server`](../server/README.ja.md) — Express HTTP サーバーと `createApp`
