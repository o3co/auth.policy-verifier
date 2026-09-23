# @o3co/auth.policy-verifier.core

最終更新: 2026-09-24

auth.policy-verifier の型定義・評価エンジン・モジュール基盤。コレクター、ルール、モジュールが実装すべきインターフェースを定義するパッケージです。

**Runtime:** `Map.groupBy` をサポートするサーバー／エッジ JavaScript ランタイムが対象です — Node.js 22+（`engines.node` で宣言しており、古い Node ではインストール時にブロックされます）、Cloudflare Workers、Vercel Edge、Deno、Bun。ブラウザは設計上対象外です（認可判定はサーバー側で enforcement する必要があるため）。同梱の `server` パッケージは引き続き Node 専用です。

## 責務と役割

auth.policy-verifier の最下層です。`builtins`、`cedar`、`server` がこのパッケージに依存し、このパッケージは何にも依存しません（`package.json` に `dependencies` はありません）。

- **所有するもの:** 判定の語彙となる契約 — `CollectorContext`、`Attributes`、コレクターとルールのインターフェース、`Decision` — と、判定に至る手順: 上限付きのコレクターパイプラインと `evaluate()`、その意味論（`ruleType` グループ内は OR、グループ間は AND、デフォルト deny、上限超過は fail-closed）、エラーと失敗元の記録。5 つの `ATTR_*` キーと属性キーの予約レジストリ、`Logger` ポート、合成の単位となる `Module` / `Registry` の形。
- **所有しないもの:** トランスポート（HTTP は `server`）、クレデンシャル検証（subject は確立済みで届く。`KeyResolver` とトークン認証器は `server`）、ポリシーエンジン（`AsyncRule` がその接続点で、`cedar` がその一つ）、具体的なコレクターとルール（`builtins` または利用側）、ドメイン固有の属性語彙、設定の読み込み（上限値はすべて数値として渡されます）。
- **別パッケージである理由:** すべてのコレクター・ルール・モジュールが実装する契約なので、トランスポート・クレデンシャル・ポリシーエンジンへの依存を持ち込まず、上記のエッジランタイムで動きます（`server` は Node 専用のまま）。デプロイメントは server や builtins を差し替えてもこのパッケージはそのまま使えます。

ソースディレクトリの責務・役割・不変条件: [`src/README.md`](src/README.md)（英語）。

## インストール

```bash
npm install @o3co/auth.policy-verifier.core
```

## パブリック API

パッケージが export するものは [`src/index.mts`](src/index.mts) にすべて並んでいます。以下の各項目は定義しているファイルへリンクしており、名前とシグネチャはそちらの doc コメントが正です。この節では各部品が何をするかを説明します。

### evaluate

`evaluate(attrs, rules, options?)` とその `EvaluateOptions` は [`src/evaluate.mts`](src/evaluate.mts) に定義されています。オプションは `onEmptyRuleSet`（既定 `"deny"`）、`ruleTimeoutMs` と `evaluateDeadlineMs`（非同期ルールの予算。既定は [`src/collectorLimits.mts`](src/collectorLimits.mts) の `DEFAULT_RULE_TIMEOUT_MS` / `DEFAULT_EVALUATE_DEADLINE_MS` で、2000 / 5000 ms）、呼び出し側の `signal`、そして `failures`（[`FailureRecord`](#failurerecord)）です。

収集した属性をルールセットに対して評価します。ルールは `ruleType` でグループ化され、グループ内はいずれかのルールが通れば満足（OR）、すべてのグループが満たされた場合に許可（グループ間 AND）となります。結果は `Decision` で、`reason` 付きの allow か、`code`・`message`・`reason` 付きの deny のどちらかです。

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

[`src/AttributePipeline.mts`](src/AttributePipeline.mts) に定義されています。`AttributeCollector` のリストと任意の [コレクターの上限](#コレクターの上限) から構築し、`collect(request, { failures }?)` はマージ済みの `Attributes` に解決します。

コレクターを並列実行し（同時に `CollectorLimits.concurrency` 本まで、残りはその後ろで待機）、結果をマージします。配列値はコレクター順に結合されます。それ以外の値は 1 度だけ書くか、同じ値で書き直すことはできますが、2 つのコレクターが 1 つのキーに*異なる*値を書くと `AttributeConflictError` を送出し、server はこれを deny として返します (#174)。

fan-out には上限があります — [コレクターの上限](#コレクターの上限) を参照。`collect` は `CollectorRequest`（`signal` を持たないリクエスト）を受け取り、各コレクター用の `signal` は pipeline が供給します。

### RulePipeline

[`src/RulePipeline.mts`](src/RulePipeline.mts) に定義されています。`RuleCollector` のリストと任意の [コレクターの上限](#コレクターの上限) から構築し、`collect(request, { failures }?)` は 1 本のフラットなルールリストに解決します。

すべてのコレクターを `AttributePipeline` と同じ上限（`CollectorLimits.concurrency` を含む）で並列実行し、結果を単一の配列にフラット化します。コレクターは同期の `Rule`、非同期の `AsyncRule`、あるいはその両方を返せます。

### コレクターの上限

`CollectorLimits` とその既定値は [`src/collectorLimits.mts`](src/collectorLimits.mts) に定義されています。任意の上限が 3 つあります: `collectorTimeoutMs`（コレクター 1 本の予算、既定 2000 ms）、`deadlineMs`（pipeline 1 本の fan-out 全体、既定 5000 ms）、`concurrency`（同時実行数、既定 8）。

コレクターはデータベースや HTTP API を呼ぶため、素の `Promise.all` で走らせる pipeline には待つのをやめる手段がありませんでした。各コレクターには `CollectorContext.signal` で専用の `AbortSignal` と専用の予算が渡され、fan-out 全体にはデッドラインが付き、同時に走るのは `concurrency` 本までです。何も渡さなければすべて既定値が適用されるため、上限なしで構築した pipeline も保護されています。正の整数でない上限や、タイマーが保持できる値（`MAX_TIMER_MS`）を超えるミリ秒予算はコンストラクタが `RangeError` で拒否します（黙って無視しません） — `concurrency: 0` は「何も集めずに解決する」になってしまうためです。

**上限に達した場合は `CollectorTimeoutError` を送出し、部分的な解決は決してしません。** 部分的な attribute は Rule の入力を弱め、部分的な Rule はポリシー自体を弱めます — ルールが空なら `{ onEmptyRuleSet: "allow" }` の下では allow です。認可経路に「集まったぶんで答える」の安全な形は存在しません。

### FailureRecord

`FailureRecord` と `FailureSource` は [`src/failureSource.mts`](src/failureSource.mts) に定義されています。`FailureSource` は 3 種類のいずれかです: `collector`（pipeline とコレクター名を持つ）、`deadline`（pipeline を持つ）、`rule`（`ruleType` と `code` を持つ）。

**1 つの decision の**失敗がどこから来たかを記録します (#200)。decision ごとに 1 つ作り、同じものを両方の collect と `evaluate` に渡し（`collect(request, { failures })`、`evaluate(attrs, rules, { failures })`）、decision を失敗させた値で `sourceOf` を問い合わせます。pipeline と `evaluate` はエラーを**そのまま** reject します — 出どころはエラーを包むのではなくエラーの横に記録されるため、クラスで deny と障害を見分ける transport も、自分のエラーと照合する呼び出し側も、throw されたものをそのまま受け取ります。

記録されるもの: reject / throw した、または自分の予算を超えたコレクター（`collector`）、デッドラインを超えた pipeline（`deadline` — 特定のコレクターの責任ではない）、`verify` が throw した / `decide` が reject した / ルールの予算を超えたルール（`rule`）。出どころは必ずランナーまたは評価器自身が記録し、エラーから読み取ることはありません。そのため自前で作った `CollectorTimeoutError` を throw したコレクターは、そのエラーが何を名乗っていても自分の位置で記録されます。コレクターは位置（サーバーの設定パスと同じ綴り）と、クラス名が識別子の形で 64 文字以内ならクラス名で呼ばれます — `attribute.collectors[1] (EntitlementStoreCollector)`、オブジェクトリテラルなら `rule.collectors[0]`。`CollectorTimeoutError.collector` が予算を超えたコレクターを呼ぶ名前も同じです。

記録は throw された値（プリミティブを含む）をキーにし、**同じ値に対しては最初に記録された出どころが優先**されます: 1 つの decision の 2 つのコレクターが同じ共有オブジェクトで失敗した場合、先に reject が届いた方が名指しされます。decision 単位なのは意図的です — プロセス全体では何も保持しないため、同じ共有オブジェクトで失敗した並行 decision がこちらの記録を書き換えることはありません。複数の decision で共有しないでください。呼び出し側の abort 理由（コレクターやルール自身の signal が abort された後の reject は、abort させた側のもの）と、どの pipeline / 評価器も記録していないものには `undefined` を返します。

### Registry\<T\>

[`src/modules/Registry.mts`](src/modules/Registry.mts) に定義されている、名前をキーにしたレジストリです。`register`・`get`・`has`・`entries`（ペアのスナップショット）を持ちます。`register` は重複名で、`get` は未登録の名前で例外をスローするため、登録済みの名前は確認なしに引けます。

### Module / ModuleContext

`Module`、`ModuleContext`、`PathResolver` と 3 つのファクトリー型（`AttributeCollectorFactory`、`RuleCollectorFactory`、`ResourceParserFactory`）は [`src/modules/types.mts`](src/modules/types.mts) に定義されています。モジュールは `name` と非同期の `init(context)` を持ち、コンテキストは `pathResolver`、モジュールの `config`、そして attribute collector・rule collector・resource parser のファクトリーそれぞれの `Registry` を運びます。

モジュールは `init` 内で attribute collector・rule collector・resource parser のファクトリーをレジストリに登録します。設定値は `config` を通じて渡されます。`RuleCollectorFactory` は、起動に I/O が要るコレクターのために `Promise` を返せます (#225)。`createApp` はそれを await します。ホスト側はこれより広いコンテキストでモジュールを初期化できます: デフォルト server の `ServerModuleContext`（`@o3co/auth.policy-verifier.server`、定義は [`jwt/keyResolver.mts`](../server/src/jwt/keyResolver.mts)）はここに 2 つのレジストリを足しています — JWT 鍵リゾルバーの `keyResolverRegistry` と、トークン認証器の `tokenAuthenticatorRegistry`（#219。`createApp` がどのモジュールより先に組み込みの `"jwt"` を登録し、モジュールは独自の名前で代替を追加でき、`oauth.authenticator` がどれを使うかを選びます）。どちらかを必要とするモジュールは `Module<ServerModuleContext>` を宣言します。

### 型一覧

残りの契約型を、定義しているファイルごとにまとめます:

- [`src/types.mts`](src/types.mts) — 判定の契約。
  - `Resource`（パース済みリソース: 元の `raw` 文字列、`resourceType`、任意の `resourceId`）と、生の文字列をそれに変換する `ResourceParser`。自分が扱う構文でない文字列には `ResourceParseError` をスローします。
  - `CollectorContext` — すべてのコレクターに渡される入力: 検証済みの `subject`、`resource`、`action`、コレクター専用の `signal`、そして任意でトランスポートが設定した `headers`、呼び出し側の `requestContext`、生の `credential`（コンポジションが opt-in したときだけ。ログに出してはいけません）。`CollectorRequest` は pipeline に渡されるもので、コレクター単位の `signal` を除いたものに、pipeline が自分の signal に連結する呼び出し側キャンセル用の任意の `signal` を加えたものです。
  - `SubjectAttributes` — トランスポートが設定する、サブジェクトの検証済み属性。core はフィールドを定めません。デフォルト server の組み込み authenticator の下では、検証済み JWT のクレーム（`sub`、`azp`、`scope` …）と `authScheme`（トークンが載っていた `Authorization` のスキーム。クレームではない）です。
  - `Attributes` — コレクターが組み立て `AttributePipeline` がマージする、変更可能な属性マップ。`ReadonlyAttributes` — ルールが判定に使う読み取り専用のビュー。評価器は同じライブなマップをすべてのルールに渡すため、ルールが書き込むと後続のすべてのグループの入力が変わってしまいます。
  - `AttributeCollector` と `RuleCollector` — 2 種類のコレクターのインターフェース。rule collector は `Rule`、`AsyncRule`、またはその両方（`AnyRule`）を返せます。
  - `Rule` — `ruleType`、`code`、`message` と、属性についての決定的で副作用のない関数でなければならない `verify`。`AsyncRule` — 同じ契約を、デッドラインの下で非同期の `decide` で答えるもの (#225)。`isAsyncRule` で見分けます。[AGENTS.md — Collector / Rule / Attribute Contract](../../AGENTS.md#collector--rule--attribute-contract) を参照。
  - `Decision`、`DecisionReason`、`RuleGroupOutcome`、`RuleOutcome` — 答えとその説明。[evaluate](#evaluate) で説明したとおりです。`RuleOutcome` はルールが報告した `evaluation` を持つことがあり (#244)、`evaluate()` が検査して freeze します。
  - `ReportRuleEvaluation` と `RuleEvaluation`（および `RuleEvaluationStatus`） — ポリシー評価器を前段に持つルールが、1 つの答えの背後にある評価を報告する手段: 評価器が走ったか、どのポリシーリビジョンに対してか（`null` は明示的な「不明」）。`evaluate()` は呼び出しごとに reporter を 1 つ作り、報告されたリビジョンは `POLICY_REVISION_PATTERN` と `POLICY_REVISION_MAX_LENGTH` に照らして検査されます。[docs/extending.ja.md](../../docs/extending.ja.md#answer-の背後にある-evaluation-を報告する) を参照。
  - `Role` — ロール名とそのパーミッション。
- [`src/errors.mts`](src/errors.mts) — エラークラス。クラスとして export されているので `instanceof` で絞り込めます: `ResourceParseError`（拒否された `raw` と理由の `detail` を持つ。サーバーエラーではなく**リクエスト**エラーで、トランスポートは 400 系で返す）、`CollectorTimeoutError`（`pipeline`、`limit`、`timeoutMs`、コレクター単位のタイムアウトなら `collector` を持つ。**劣化ではなく deny**）、`RuleTimeoutError`、`AttributeConflictError`。
- [`src/collectorLimits.mts`](src/collectorLimits.mts) — `CollectorLimits`（[コレクターの上限](#コレクターの上限) を参照）、`CollectOptions`（両 pipeline の `collect` の第 2 引数 `{ failures }`）、`DEFAULT_*` の上限値。
- [`src/untrusted.mts`](src/untrusted.mts) — `UntrustedRequestContext`。`requestContext` の型で、呼び出し側自身のデータを封印したものです。読むには明示的な `readUntrustedRequestContext(...)` が要り、トランスポート境界で `markUntrustedRequestContext(...)` が作ります。[docs/extending.ja.md — 信頼境界](../../docs/extending.ja.md#信頼境界-requestcontext-は呼び出し側のもの) を参照。
- [`src/logging/Logger.mts`](src/logging/Logger.mts) — `Logger` ポート。[`src/logging/consoleLogger.mts`](src/logging/consoleLogger.mts) がコンソール実装です。

`KeyResolver` / `KeyResolverFactory` は core の型ではありません。トークンクレデンシャルの配管であり、`@o3co/auth.policy-verifier.server` にあります (#170)。

### 定数

[`src/keys.mts`](src/keys.mts) に定義されている `ATTR_*` 定数は OAuth 2.0 / OIDC および RBAC の標準語彙に限定しています。これらはこのエンジンを利用するすべてのサービスが共通して扱う概念（JWT クレーム、OAuth スコープ、RBAC のロール・パーミッション）です。業務ドメイン固有の属性キーは core ではなく、利用側サービスに属します。利用側は独自のキー定数を定義し、同じ `Attributes` マップを介して読み書きします。

- `ATTR_SCOPES` — OAuth スコープ
- `ATTR_PERMISSIONS` — 明示的なパーミッション
- `ATTR_ROLES` — ロール
- `ATTR_USER_ID` — サブジェクトのユーザー ID（JWT `sub`）
- `ATTR_CLIENT_ID` — クライアント ID（JWT `azp`）

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

レジストリの export はすべて [`src/keys.mts`](src/keys.mts) にあります:

- `RESERVED_ATTRIBUTE_KEYS` — 予約済みキー全体を表す **ライブな** 読み取り専用の集合。判定が必要なその場で読むこと。モジュールスコープでコピーしてはいけません。
- `reserveAttributeKeys` — パッケージのキーを予約する。同一 owner なら冪等、別 owner が同じキーを要求した場合は拒否。
- `attributeKeyReservation` — キーの所有者。拒否メッセージが core と決めつけずにパッケージ名を出せる。
- `suggestUnreservedAttributeKey` — どのパッケージも予約していない代替名。拒否メッセージが提案する名前。
- `CORE_ATTRIBUTE_KEY_OWNER` — core 自身の 5 キーの owner 名。

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

- [`src/README.md`](src/README.md) — このパッケージのソースディレクトリの責務・役割・不変条件（英語）
- [ルート README](../../README.ja.md) — セットアップ全体、設定、サーバー利用方法
- [`@o3co/auth.policy-verifier.builtins`](../builtins/README.ja.md) — 組み込みコレクター、ルール、リソースパーサー
- [`@o3co/auth.policy-verifier.server`](../server/README.ja.md) — Express HTTP サーバーと `createApp`
