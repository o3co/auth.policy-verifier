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
  /** Milliseconds one asynchronous rule may take. Defaults to DEFAULT_RULE_TIMEOUT_MS (2000). */
  ruleTimeoutMs?: number
  /** Milliseconds all asynchronous rules may take together. Defaults to DEFAULT_EVALUATE_DEADLINE_MS (5000). */
  evaluateDeadlineMs?: number
  /** The caller's signal; aborting it aborts the asynchronous rule in flight with its reason. */
  signal?: AbortSignal
  /** This decision's FailureRecord: which rule threw, rejected or overran a budget (#200). */
  failures?: FailureRecord
}

function evaluate(attrs: Attributes, rules: AnyRule[], options?: EvaluateOptions): Promise<Decision>
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

ルールのリストにはどちらの種類のルールも混在できます (#225)。同期の `Rule` は `verify` で、`AsyncRule` は `ruleTimeoutMs` の制限下で `decide` を await して問い合わせます。どちらも収集順に 1 つずつ問い、グループ内で最初に通ったルール以降の代替ルールは種類を問わず実行されません。`evaluate` が非同期なのはそのためだけで、同期ルールだけのリストは同じターン内で答えが出ます。非同期ルールが予算を超えたとき、またはルール全体で `evaluateDeadlineMs` を超えたときは `RuleTimeoutError` で reject します（`limit: "rule"` または `"deadline"`。transport にとっては deny であり、pass にはなりません）。`signal` が abort されれば呼び出し側の abort 理由で、ルールが throw / reject すればその値でそのまま reject し、[`FailureRecord`](#failurerecord) が渡されていればそのルールを `failures` に記録します。

### AttributePipeline

```typescript
class AttributePipeline {
  constructor(collectors: AttributeCollector[], limits?: CollectorLimits)
  collect(request: CollectorRequest, options?: { failures?: FailureRecord }): Promise<Attributes>
}
```

すべてのコレクターを並列実行し、結果をマージします。配列値は結合され、それ以外の型は後書きが優先されます。

fan-out には上限があります — [コレクターの上限](#コレクターの上限) を参照。`collect` は `CollectorRequest`（`signal` を持たないリクエスト）を受け取り、各コレクター用の `signal` は pipeline が供給します。

### RulePipeline

```typescript
class RulePipeline {
  constructor(collectors: RuleCollector[], limits?: CollectorLimits)
  collect(request: CollectorRequest, options?: { failures?: FailureRecord }): Promise<AnyRule[]>
}
```

すべてのコレクターを並列実行し、結果を単一の配列にフラット化します。上限は `AttributePipeline` と同じです。コレクターは同期の `Rule`、非同期の `AsyncRule`、あるいはその両方を返せます。

### コレクターの上限

```typescript
interface CollectorLimits {
  collectorTimeoutMs?: number; // コレクター 1 本の予算;        既定 2000
  deadlineMs?: number;         // pipeline 単位の fan-out 全体; 既定 5000
  concurrency?: number;        // 同時実行数;                   既定 8
}
```

コレクターはデータベースや HTTP API を呼ぶため、素の `Promise.all` で走らせる pipeline には待つのをやめる手段がありませんでした。各コレクターには `CollectorContext.signal` で専用の `AbortSignal` と専用の予算が渡され、fan-out 全体にはデッドラインが付き、同時に走るのは `concurrency` 本までです。何も渡さなければすべて既定値が適用されるため、上限なしで構築した pipeline も保護されています。正の整数でない上限はコンストラクタが `RangeError` で拒否します（黙って無視しません） — `concurrency: 0` は「何も集めずに解決する」になってしまうためです。

**上限に達した場合は `CollectorTimeoutError` を送出し、部分的な解決は決してしません。** 部分的な attribute は Rule の入力を弱め、部分的な Rule はポリシー自体を弱めます — ルールが空なら `{ onEmptyRuleSet: "allow" }` の下では allow です。認可経路に「集まったぶんで答える」の安全な形は存在しません。

### FailureRecord

```typescript
type FailureSource =
  | { kind: "collector"; pipeline: "attribute" | "rule"; collector: string }
  | { kind: "deadline"; pipeline: "attribute" | "rule" }
  | { kind: "rule"; ruleType: string; code: string }

class FailureRecord {
  record(error: unknown, source: FailureSource): void
  sourceOf(error: unknown): FailureSource | undefined
}
```

**1 つの decision の**失敗がどこから来たかを記録します (#200)。decision ごとに 1 つ作り、同じものを両方の collect と `evaluate` に渡し（`collect(request, { failures })`、`evaluate(attrs, rules, { failures })`）、decision を失敗させた値で `sourceOf` を問い合わせます。pipeline と `evaluate` はエラーを**そのまま** reject します — 出どころはエラーを包むのではなくエラーの横に記録されるため、クラスで deny と障害を見分ける transport も、自分のエラーと照合する呼び出し側も、throw されたものをそのまま受け取ります。

記録されるもの: reject / throw した、または自分の予算を超えたコレクター（`collector`）、デッドラインを超えた pipeline（`deadline` — 特定のコレクターの責任ではない）、`verify` が throw した / `decide` が reject した / ルールの予算を超えたルール（`rule`）。出どころは必ずランナーまたは評価器自身が記録し、エラーから読み取ることはありません。そのため自前で作った `CollectorTimeoutError` を throw したコレクターは、そのエラーが何を名乗っていても自分の位置で記録されます。コレクターは位置（サーバーの設定パスと同じ綴り）と、クラス名が識別子の形で 64 文字以内ならクラス名で呼ばれます — `attribute.collectors[1] (EntitlementStoreCollector)`、オブジェクトリテラルなら `rule.collectors[0]`。`CollectorTimeoutError.collector` が予算を超えたコレクターを呼ぶ名前も同じです。

記録は throw された値（プリミティブを含む）をキーにし、**同じ値に対しては最初に記録された出どころが優先**されます: 1 つの decision の 2 つのコレクターが同じ共有オブジェクトで失敗した場合、先に reject が届いた方が名指しされます。decision 単位なのは意図的です — プロセス全体では何も保持しないため、同じ共有オブジェクトで失敗した並行 decision がこちらの記録を書き換えることはありません。複数の decision で共有しないでください。呼び出し側の abort 理由（コレクターやルール自身の signal が abort された後の reject は、abort させた側のもの）と、どの pipeline / 評価器も記録していないものには `undefined` を返します。

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
interface Module<C extends ModuleContext = ModuleContext> {
  name: string
  init(context: C): Promise<void>
}

interface ModuleContext {
  pathResolver: PathResolver
  config: Record<string, unknown>
  attributeCollectorRegistry: Registry<AttributeCollectorFactory>
  ruleCollectorRegistry: Registry<RuleCollectorFactory>
  resourceParserRegistry: Registry<ResourceParserFactory>
}
```

モジュールは `init` 内で attribute collector・rule collector・resource parser のファクトリーをレジストリに登録します。設定値は `config` を通じて渡されます。ホスト側はこれより広いコンテキストでモジュールを初期化できます: デフォルト server の `ServerModuleContext`（`@o3co/auth.policy-verifier.server`）はここに JWT 鍵リゾルバーのレジストリを足しており、それを必要とするモジュールは `Module<ServerModuleContext>` を宣言します。

### 型一覧

| 型 | 説明 |
| --- | --- |
| `Resource` | `{ raw: string; resourceType: string; resourceId?: string }` — パース済みリソース |
| `ResourceParser` | `parse(raw: string): Resource` — 生のリソース文字列を `Resource` に変換する。パース対象の構文に合わない文字列には `ResourceParseError` を送出する |
| `ResourceParseError` | `raw`（拒否した文字列）と `detail`（理由）を持つ `Error` サブクラス。サーバーエラーではなく**リクエスト**エラーであり、トランスポート層は 400 系で応答する。クラスとして export されるため `instanceof` で絞り込める |
| `CollectorContext` | 各コレクターに渡される入力: `subject`、`resource`、`action`、`signal`、省略可能な `headers` と `requestContext` |
| `CollectorRequest` | pipeline が受け取る形: コレクター単位の `signal` を除いた `CollectorContext`。`signal` は pipeline が供給する。こちらの省略可能な `signal` は呼び出し側のキャンセルで、pipeline 側の signal に連結される |
| `CollectorLimits` | `{ collectorTimeoutMs?, deadlineMs?, concurrency? }` — pipeline が fan-out に課す上限。[コレクターの上限](#コレクターの上限) を参照 |
| `CollectorTimeoutError` | コレクターが予算を、または fan-out がデッドラインを超えたときに送出される `Error` サブクラス。`pipeline` / `limit` / `timeoutMs` と、コレクター単位のタイムアウトでは `collector`（[`FailureRecord`](#failurerecord) と同じ名前）を持つ。**劣化ではなく deny** — pipeline は何も返さない |
| `FailureSource` | `{ kind: "collector"; pipeline; collector } \| { kind: "deadline"; pipeline } \| { kind: "rule"; ruleType; code }` — 失敗の出どころ。[FailureRecord](#failurerecord) を参照 |
| `CollectOptions` | `{ failures?: FailureRecord }` — 両 pipeline の `collect` の第 2 引数。[FailureRecord](#failurerecord) を参照 |
| `UntrustedRequestContext` | `requestContext` の型 — 呼び出し側のデータであり、読むには明示的な `readUntrustedRequestContext(...)` が必要な形で封じられている。トランスポート境界で生成するのは `markUntrustedRequestContext(...)`。[docs/extending.ja.md — 信頼境界](../../docs/extending.ja.md#信頼境界-requestcontext-は呼び出し側のもの) を参照 |
| `Attributes` | `Map<string, unknown>` — サブジェクト属性のバッグ。可変: コレクターがこれを組み立て、`AttributePipeline` がマージする |
| `ReadonlyAttributes` | `ReadonlyMap<string, unknown>` — Rule が判定対象として受け取るビュー。評価器は同一の live map をすべての Rule に渡すため、書き込む Rule は以降の全グループの入力を書き換えてしまう |
| `AttributeCollector` | `collect(context: CollectorContext): Promise<Attributes>` |
| `Rule` | `{ ruleType: string; code: string; message: string; verify(attrs: ReadonlyAttributes): RuleAnswer }` — `verify` は `attrs` の決定的かつ副作用のない関数でなければならない。[AGENTS.md — Collector / Rule / Attribute Contract](../../AGENTS.md#collector--rule--attribute-contract) を参照 |
| `AsyncRule` | `{ ruleType: string; code: string; message: string; readonly async: true; decide(attrs: ReadonlyAttributes, signal: AbortSignal): Promise<RuleAnswer> }` — `Rule` と同じ契約で I/O を行うもの、デッドラインのもとで実行される (#225)。`isAsyncRule` は判別子 `async` を読む |
| `RuleCollector` | `collect(context: CollectorContext): Promise<AnyRule[]>` — `Rule`、`AsyncRule`、またはその両方 |
| `Decision` | `{ decision: "allow"; reason: DecisionReason } \| { decision: "deny"; code: string; message: string; reason: DecisionReason }` |
| `DecisionReason` | `{ groups: RuleGroupOutcome[] }` |
| `RuleGroupOutcome` | `{ ruleType: string; passed: true; evaluated: RuleOutcome[]; satisfiedBy: RuleOutcome } \| { ruleType: string; passed: false; evaluated: RuleOutcome[] }` — `evaluated` は実際に走ったルールを評価順に列挙し、`satisfiedBy` は通過グループを満たしたルールを指す |
| `RuleOutcome` | `{ code: string; message: string; passed: boolean; evaluation?: RuleEvaluation }` — `evaluation` は、この answer の背後にある evaluation について Rule が報告したもの (#244)。`evaluate()` が検査して freeze する。報告が無ければキー自体が無い |
| `RuleAnswer` | `boolean \| RuleVerdict` — `verify` / `decide` が返せるもの。`ruleAnswerPassed(answer)` で読むこと。truthiness で読まない: 失敗した verdict はオブジェクトである |
| `RuleVerdict` | `{ passed: boolean; evaluation?: RuleEvaluation }` — policy evaluator を背後に持つ Rule の answer。1 回の呼び出しについての事実なので戻り値になっている。[docs/extending.ja.md](../../docs/extending.ja.md#answer-の背後にある-evaluation-を報告する) を参照 |
| `RuleEvaluation` | `{ status: "not_invoked" } \| { status: "completed" \| "failed"; revision: string } \| { status: "completed" \| "failed"; revision: null; loadedRevision?: string }` — `revision` は evaluator が「何を評価したか」を保証するときだけ文字列になり、`null` は明示的な「不明」。参照は `scheme:encoded`（`POLICY_REVISION_PATTERN`、最大 `POLICY_REVISION_MAX_LENGTH` 文字） |
| `Role` | `{ name: string; permissions: string[] }` |
| `SubjectAttributes` | `{ readonly [key: string]: unknown }` — トランスポートが保証するサブジェクトの検証済み属性バッグ。core はフィールド名を一切定めない。デフォルト server の下ではキーは検証済み JWT のクレーム（`sub`、`azp`、`scope`、…）と `authScheme`（クレームではなく、トークンが到着した `Authorization` スキーム） |
| `PathResolver` | `(specifier: string) => string` — モジュール相対パスを解決する |
| `AttributeCollectorFactory` | config から `AttributeCollector` を生成するファクトリー関数 |
| `RuleCollectorFactory` | config から `RuleCollector` を生成するファクトリー関数。boot に I/O が要る collector のために `Promise` を返してもよい (#225)。`createApp` が await する |
| `ResourceParserFactory` | config から `ResourceParser` を生成するファクトリー関数 |

`KeyResolver` / `KeyResolverFactory` は core の型ではありません。トークンクレデンシャルの配管であり、`@o3co/auth.policy-verifier.server` にあります (#170)。

### 定数

`ATTR_*` 定数は OAuth 2.0 / OIDC および RBAC の標準語彙に限定しています。これらはこのエンジンを利用するすべてのサービスが共通して扱う概念（JWT クレーム、OAuth スコープ、RBAC のロール・パーミッション）です。業務ドメイン固有の属性キーは core ではなく、利用側サービスに属します。利用側は独自のキー定数を定義し、同じ `Attributes` マップを介して読み書きします。

| 定数 | 値 | 説明 |
| --- | --- | --- |
| `ATTR_SCOPES` | `"scopes"` | OAuth スコープの属性キー |
| `ATTR_PERMISSIONS` | `"permissions"` | 明示的なパーミッションの属性キー |
| `ATTR_ROLES` | `"roles"` | ロールの属性キー |
| `ATTR_USER_ID` | `"userId"` | サブジェクトユーザー ID（JWT `sub`）の属性キー |
| `ATTR_CLIENT_ID` | `"clientId"` | クライアント ID（JWT `azp`）の属性キー |

### 属性キーのレジストリ

この 5 つはエンジンが判断に使うキーなので、呼び出し側のデータを昇格させる Collector が書き込んではいけません（[docs/extending.ja.md](../../docs/extending.ja.md#信頼境界-requestcontext-は呼び出し側のもの)）。ただし、そうしたキーを core が列挙し切ることはできません。独自の属性語彙を持つパッケージ（`@o3co/auth.policy-verifier.cedar` は `requestAction` / `requestResourceType` / `requestResourceId` / `requestResourceRaw` を所有）は core からは見えないからです。そのため予約は固定集合ではなくレジストリであり、各パッケージが自分の語彙を予約します:

```typescript
import { reserveAttributeKeys } from '@o3co/auth.policy-verifier.core'

export const ATTR_SUBSCRIBER_DID = 'subscriberDid' as const

// 定数のすぐ横、モジュールスコープで呼ぶ — 順序が保証される理由は
// reserveAttributeKeys の doc コメントを参照。
reserveAttributeKeys({
  owner: '@example/subscriber-policy',
  keys: [ATTR_SUBSCRIBER_DID],
  reason: 'resolved from the verified subject by SubscriberDidCollector',
})
```

| export | 役割 |
| --- | --- |
| `RESERVED_ATTRIBUTE_KEYS` | 予約済みキー全体の **ライブな** `ReadonlySet`。判定が必要なその場で読むこと。モジュールスコープでコピーしてはいけません |
| `reserveAttributeKeys({ owner, keys, reason? })` | パッケージのキーを予約する。同一 owner なら冪等、別 owner が同じキーを要求した場合は拒否 |
| `attributeKeyReservation(key)` | キーの所有者。拒否メッセージが core と決めつけずにパッケージ名を出せる |
| `suggestUnreservedAttributeKey(key)` | どのパッケージも予約していない代替名。拒否メッセージが提案する名前 |
| `CORE_ATTRIBUTE_KEY_OWNER` | core 自身の 5 キーの owner 名 |

このレジストリを参照する guard が builtins の `RequestContextAttributeCollector` です。自作の Collector も同じレジストリを参照してください。

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
// `subject` はトランスポートが保証する属性 — デフォルト server は検証済み
// JWT クレームを展開して渡す。
const context = { subject: verifiedClaims, resource, action: 'read' }

const attrs = await new AttributePipeline([new PayloadScopeCollector()]).collect(context)
const rules = await new RulePipeline([new ResourceActionScopeRuleCollector()]).collect(context)
const decision = await evaluate(attrs, rules)
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
