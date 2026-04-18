# @o3co/auth.policy-verifier.core

auth.policy-verifier の型定義・評価エンジン・モジュール基盤。コレクター、ルール、モジュールが実装すべきインターフェースを定義するパッケージです。

**Runtime:** Node.js 22+。本パッケージを含む `auth.policy-verifier` 群は現時点で Node.js 専用です。browser / edge ランタイム対応は今後の課題として別 issue で追跡します。

## インストール

```bash
npm install @o3co/auth.policy-verifier.core
```

## パブリック API

### evaluate

```typescript
function evaluate(attrs: Attributes, rules: Rule[]): Decision
```

収集した属性をルールセットに対して評価します。ルールは `ruleType` でグループ化され、グループ内はいずれかのルールが通れば満足（OR）、すべてのグループが満たされた場合に許可（グループ間 AND）となります。戻り値は `{ decision: "allow" }` または `{ decision: "deny"; code: string; message: string }` です。

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
}
```

モジュールは `init` 内でコレクターやパーサーのファクトリーをレジストリに登録します。設定値は `config` を通じて渡されます。

### 型一覧

| 型 | 説明 |
| --- | --- |
| `Resource` | `{ raw: string; resourceType: string; resourceId?: string }` — パース済みリソース |
| `ResourceParser` | `parse(raw: string): Resource` — 生のリソース文字列を `Resource` に変換する |
| `CollectorContext` | 各コレクターに渡される入力: `payload`、`resource`、`action`、省略可能な `headers` と `requestContext` |
| `Attributes` | `Map<string, unknown>` — サブジェクト属性のバッグ |
| `AttributeCollector` | `collect(context: CollectorContext): Promise<Attributes>` |
| `Rule` | `{ ruleType: string; code: string; message: string; verify(attrs: Attributes): boolean }` |
| `RuleCollector` | `collect(context: CollectorContext): Promise<Rule[]>` |
| `Decision` | `{ decision: "allow" } \| { decision: "deny"; code: string; message: string }` |
| `Role` | `{ name: string; permissions: string[] }` |
| `VerifierPayload` | デコード済み JWT クレーム: `sub`、`azp`、`scope`、`iss`、`aud`、`exp`、`iat`、`token`、`tokenType`、および任意の追加クレーム |
| `PathResolver` | `(specifier: string) => string` — モジュール相対パスを解決する |
| `AttributeCollectorFactory` | config から `AttributeCollector` を生成するファクトリー関数 |
| `RuleCollectorFactory` | config から `RuleCollector` を生成するファクトリー関数 |
| `ResourceParserFactory` | config から `ResourceParser` を生成するファクトリー関数 |

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
