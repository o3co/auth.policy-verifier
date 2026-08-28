# auth.policy-verifier の拡張

本ガイドは、カスタム `Rule` / `AttributeCollector` の書き方を説明します。[`@o3co/auth.policy-verifier.builtins`](../packages/builtins/README.ja.md) の組み込み実装を補完する位置づけです。

## 位置づけ: builtins は基本セットであり、網羅カタログではない

`@o3co/auth.policy-verifier.builtins` は、一般的なユースケースをカバーする小さな Rule / Collector 群を意図的に提供します: permission / scope チェック、属性の等価 / 包含 / 比較、subject ID 抽出、静的な permission と role。

このパッケージは [OPA](https://www.openpolicyagent.org/) や [Cedar](https://www.cedarpolicy.com/) のような **網羅的な演算子カタログではありません**。それらのシステムは DSL 内でポリシーを書くため、エンジンが提供する演算子の外側に出られず、広範な組み込み演算子面が必要になります。

auth.policy-verifier は異なる立場を取ります。ポリシーは TypeScript コードであり、`Rule` / `AttributeCollector` は小さく安定したインターフェースです。プロジェクト固有のロジックに対してカスタム `Rule` を書くことは一級の操作であり、ワークアラウンドではありません。組み込みで表現できない要件があれば、自分で書いてください。組み込みの拡張を待つ必要はありません。

**カスタム Rule を書くべきとき:**

- 正規表現マッチ、CIDR マッチ、時間ウィンドウ、集合演算、ネストされた属性パスが必要。
- ポリシーが、汎用ルールからアクセスできない状態（例: DB ルックアップ）に依存する。
- 組み込みにきれいに対応しない、ドメイン固有の denial code / message を使いたい。

**組み込みを使うべきとき:**

- ロジックが 1〜2 個の属性に対する equal / not-equal / in / not-in / 数値比較で表現できる。
- プロトタイプ段階で、ドメイン固有の語彙がまだ固まっていない。

組織内の複数プロジェクトで同じカスタム Rule を書くようになったら、共有パッケージに切り出してください（例: `@yourorg/authz.rules.ipcidr`）。`builtins` を拡張させる方向には進めないでください。意図的に基本セットとして保たれています。

## カスタム Rule の書き方

`Rule` は `@o3co/auth.policy-verifier.core` で定義されます:

```ts
interface Rule {
  ruleType: string;
  code: string;
  message: string;
  verify(attrs: ReadonlyAttributes): boolean;
}
```

- `verify(attrs)` は述語です。通過時に `true`、失敗時に `false` を返します。**safe-deny 規約:** 欠落・型不一致・不正な属性は `false` を返してください。例外を投げない。例外を投げるとポリシー失敗がエラー応答になり、評価状態が漏れます。
- `attrs` はコレクターが返す `Attributes` ではなく `ReadonlyAttributes`（`ReadonlyMap<string, unknown>`）です。評価器は同一の live map を全グループの全 Rule に渡すため、書き込む Rule は以降のグループが判定される対象そのものを書き換えてしまいます。read-only ビューはそれをデバッグ作業ではなくコンパイルエラーにします。コレクター側は従来どおり可変の `Map` を組み立てて返します。
- `ruleType` は評価器が Rule をグループ化するのに使います。同じ `ruleType` の Rule は OR 結合されます（いずれか 1 つ通ればグループ通過）。異なる `ruleType` の Rule はグループ間 AND 結合されます（全グループ通過が必要）。**既定の `ruleType` は、暗黙の衝突を避けるためにルール設定を十分にエンコードしてください。** 例えば `AttrLiteralEqual` は `attr_literal_equal:${a}:${typeof v}:${String(v)}` を使います — `typeof v` セグメントは `v=true` と `v="true"` が同じ `ruleType` に畳み込まれて意図に反して OR 結合されるのを防ぎます。
- `code` は短く安定した識別子（例: `"no_permission"`、`"attr_not_equal"`）で、下流のプログラム的ハンドリングに適した文字列にしてください。**1 つの Rule が生成しうる code の集合は小さく固定に保つこと。** `code` は `auth_denials_total` メトリクスの `code` ラベルと decision ログ行の `deniedBy` になるため、リクエストごとに導出される code（例えばリソース ID を畳み込んだもの）は有界でないメトリクスラベルになります。これは、監視すべき対象を監視する仕組みそのものをメトリクスエンドポイントが落とす経路です。サーバー側は異なる値 32 個で打ち止め、それ以降を `code="other"` に潰すので、最悪でも「Prometheus が死ぬ」ではなく「メトリクスが役に立たなくなる」で済みますが、変動する部分はラベルにならない `message` に入れてください。
- `message` は人間可読な denial メッセージです。有益な情報を載せつつ、機微な属性値は漏らさないこと。

### 実例: `UserLevelAtLeast`

`userLevel` が設定値以上の数値のときに通過する Rule:

```ts
import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";

export interface UserLevelAtLeastConfig {
  threshold: number;
  group?: string;
}

export class UserLevelAtLeast implements Rule {
  readonly ruleType: string;
  readonly code = "user_level_too_low";
  readonly message: string;

  constructor(private readonly config: UserLevelAtLeastConfig) {
    if (typeof config.threshold !== "number" || Number.isNaN(config.threshold)) {
      throw new Error("UserLevelAtLeast: 'threshold' must be a number and not NaN");
    }
    // 異なる threshold の 2 インスタンスが AND 結合される（OR ではない）ように、
    // threshold を ruleType にエンコードする。
    this.ruleType = config.group ?? `user_level_at_least:${String(config.threshold)}`;
    this.message = `User level must be at least ${String(config.threshold)}.`;
  }

  verify(attrs: ReadonlyAttributes): boolean {
    const level = attrs.get("userLevel");
    if (typeof level !== "number") return false;
    return level >= this.config.threshold;
  }
}
```

要点:

- コンストラクタで設定を検証する（fail fast）。`verify()` はホットパスのため、設定を再検証しないこと。
- `verify()` は欠落・非数値属性に対して `false` を返す（safe-deny）。例外は投げない。
- 既定の `ruleType` に threshold を含めているので、`new UserLevelAtLeast({ threshold: 3 })` と `new UserLevelAtLeast({ threshold: 5 })` は異なるグループを生成し、AND 結合されます。OR 結合させたい場合（例「レベル ≥ 3 または別の基準」）は、両方に同じ `group` 文字列を渡してください。
- `Infinity` は `Number.isNaN` チェックを通過します（組み込みの `requireNumber` 規約と一致）。しかし `level >= Infinity` は有限の `level` に対して常に `false` になるため、`threshold: Infinity` は静かに常時拒否する Rule を生成します。この挙動が問題になる場合は、設定層でドメイン境界を検証してください。

## 信頼境界: `requestContext` は呼び出し側のもの

`CollectorContext` は 4 種類の入力を運びますが、呼び出し側が自由に埋められるのはそのうち 1 つだけです:

| フィールド | 出どころ | 信頼度 |
|---|---|---|
| `payload` | bearer token。署名・issuer・audience・有効期限の検証を通過済み | 検証済み |
| `resource` / `action` | リクエストボディ。形は route が検証し、`resource` は設定された `ResourceParser` が parse する | 値は呼び出し側が選ぶ／形は検証済み |
| `headers` | トランスポートが設定（現状は `x-request-id`） | トランスポート由来 |
| `requestContext` | リクエストボディの `context` をそのまま転送 | **未検証（untrusted）** |

（5 つ目のフィールド `signal` は入力ではなく、pipeline のキャンセルハンドルです。[デッドラインとキャンセル](#デッドラインとキャンセル) を参照。）

有効なトークンを持つ者は `context` に何でも書けます。`requestContext.role` を `ATTR_ROLES` に昇格させる Collector は、呼び出し側に「自分の認可入力を自分で書く」権限を渡したことになります — トークンが「誰であるか」を述べ、そのすぐ後にボディが「何をしてよいか」を述べる形です。しかもそれはたった 1 行で、隣にある `payload.sub` を昇格させる行と見分けがつきません。

データ自体には両者を区別する手がかりがないため、型に区別させます。`requestContext` の型は `UntrustedRequestContext` — プロパティアクセスでは中身に到達できない不透明な brand です:

```ts
context.requestContext?.clientIp;
//                      ^^^^^^^^ Property 'clientIp' does not exist on type 'UntrustedRequestContext'.

readUntrustedRequestContext(context.requestContext)?.clientIp; // OK
```

この unwrap こそが要点です。無意識に手が伸びることがなく、値を読むまさにその行で信頼度を明示し、呼び出し側のデータがポリシーに入る箇所すべてに（自分にとってもレビュアーにとっても）目印を付けます。unwrap した後にどうするかは実装者の判断です — どのフィールドを信頼してよいかはフレームワークには分かりません。分かるのは「明示せずに消費させてはならない」ということだけです。

unwrap した後の指針:

- **読むフィールドは毎回検証する。** 型と形を確認すること。`readUntrustedRequestContext` が返すのは `Record<string, unknown> | undefined` なので、narrowing は実装者の責任です。
- **identity や entitlement をここから昇格させない。** role、permission、scope、subject id、テナント所属は、検証済みの `payload` か、検証済み ID で問い合わせたストアから取得すること。ボディからではありません。
- **呼び出し側が嘘をついても得をしないリクエスト事実は昇格させてよい** — locale、UI ヒント、操作の形など。判断基準は「攻撃者がこのフィールドを好きな値にしたとき、何が手に入るか」です。答えが「permission」なら、それは誤った出どころです。
- **場当たり的な読み取りより宣言的な allowlist を優先する。** `builtins` の `RequestContextAttributeCollector` は、運用者が設定で名前と型を宣言したフィールドだけを昇格させます。誰も宣言していないフィールドは Rule に到達できません。

`CollectorContext` を自前で組み立てるトランスポート（自作の interceptor やテスト）は、`markUntrustedRequestContext` で受け取った時点の record をマークします。本リポジトリの verify route はボディの `context` に対してまさにこれを行っており、brand を生成できるのはこの関数だけなので、生のボディオブジェクトが誤って Collector に届くことはありません。

## デッドラインとキャンセル

各コレクターには `CollectorContext.signal` で `AbortSignal` が渡され、そのコレクターが属する fan-out には 3 つの上限が掛かります: コレクター単位のタイムアウト（既定 2 秒）、fan-out 全体のデッドライン（5 秒）、同時実行数の上限（8）。運用側は `verify.collectorTimeoutMs` / `verify.collectorDeadlineMs` / `verify.collectorConcurrency` で調整します。

**待つ相手には signal をそのまま渡してください。** キャンセルが名目でなく実効になるのはそれによってです:

```ts
async collect(context: CollectorContext): Promise<Attributes> {
  const res = await fetch(this.endpoint, { signal: context.signal });
  // …
}
```

signal を無視するコレクターも pipeline は待つのをやめます — 上限はコレクターの協力に依存しません — が、そのコレクターが始めた外向きの呼び出しは、すでに失われた決定のために依存先へ走り続けます。同時実行上限が防ごうとしているのはまさにこの積み上がりであり、signal を尊重することがそれに加担しないための手段です。

signal が abort する理由は 4 つあり、`signal.reason` がどれかを示します: このコレクターが予算を超えた、pipeline がデッドラインを超えた、兄弟コレクターがすでに決定を失敗させた、呼び出し側が去った。

**上限を超えたリクエストは deny になります** — `403` と `code: "collector_timeout"`。pipeline は `CollectorTimeoutError` を送出し、何も返しません。これは意図的です: 間に合った attribute は Rule への入力を弱め、間に合った Rule は**ポリシー**を弱め、空になれば `rule.onEmptyRuleSet = "allow"` の deployment では allow と読まれてしまいます。だから部分的な答えはそもそも存在させません。言うことが本当に無いコレクターは、速やかに空の `Map` を返してください。タイムアウトはその表明手段ではありません。

**Rule は signal を `verify` に持ち込んではいけません。** これはリクエストへの live なハンドルであり（`aborted` は勝手に変わります）、保持して `verify` で読むのは `ctx.resource` を保持するのと同じ違反です。[rule purity conformance suite](#rule-は-attrs-だけで判断する) はこれを同じ違反として検出します。

## カスタム AttributeCollector の書き方

`AttributeCollector` は `@o3co/auth.policy-verifier.core` で定義されます:

```ts
interface AttributeCollector {
  collect(context: CollectorContext): Promise<Attributes>;
}
```

- 1 つの Collector は **焦点を絞った属性キー群**を生成してください。関係のない抽出をまとめないこと。IP アドレスと User-Agent を抽出するなら Collector を 2 つに分けてください。
- 属性キーは文字列定数を使うこと。`@o3co/auth.policy-verifier.core` の `ATTR_SCOPES`、`ATTR_PERMISSIONS`、`ATTR_ROLES`、`ATTR_USER_ID`、`ATTR_CLIENT_ID` を参照。プロジェクト固有のキーは独自の定数を定義し、**core のキーを異なるセマンティクスで再利用しないこと**。
- `AttributePipeline` は全 Collector を並列実行し、結果をマージします: 配列値は連結、スカラ／オブジェクトは後勝ち。この挙動に合わせて設計し、Collector の実行順序には依存しないこと。同時に走る本数には上限があり、各 Collector には時間制限があります — [デッドラインとキャンセル](#デッドラインとキャンセル) を参照。
- `CollectorContext.requestContext` は意図的に型付けされていません。エンジンは汎用 `requestContext` Collector を提供しません。`requestContext` の形は consuming project のトランスポート層 / interceptor が定義するものであり、解釈はプロジェクトの責務だからです。必要なフィールドごとに焦点を絞った Collector を書き、形の検証はその Collector 内で行ってください。同時に唯一の未検証入力でもあります — 中身を読む前に [信頼境界](#信頼境界-requestcontext-は呼び出し側のもの) を参照してください。

### 実例: `ClientIpCollector`

`requestContext` から IP アドレスを属性として抽出する Collector:

```ts
import type {
  AttributeCollector,
  Attributes,
  CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { readUntrustedRequestContext } from "@o3co/auth.policy-verifier.core";

// プロジェクト固有の属性キー定数 — プロジェクトローカルで定義する。
export const ATTR_CLIENT_IP = "clientIp" as const;

export class ClientIpCollector implements AttributeCollector {
  async collect(context: CollectorContext): Promise<Attributes> {
    // 呼び出し側が入れた値であり、何を書くこともできた。ATTR_CLIENT_IP を読む
    // Rule は「値を選ばれてもよい」ものでなければならない。
    const ip = readUntrustedRequestContext(context.requestContext)?.clientIp;
    if (typeof ip !== "string" || ip.length === 0) {
      return new Map(); // 何も出力しない — 下流 Rule では属性欠落として safe-deny される
    }
    return new Map([[ATTR_CLIENT_IP, ip]]);
  }
}
```

要点:

- 形が不正または値が欠落している場合は空 `Map` を返すこと。キーを `null` / `undefined` に設定しない — 「欠落」と「存在するが falsy」を区別する下流 Rule が壊れやすくなるため。
- 形の検証は Collector 内で行う。`readUntrustedRequestContext` が返すのは `Record<string, unknown> | undefined` であり、それを消費する Collector が narrowing の適切な場所です。そのフィールドが取りうる値を知っているのもそこだけです。
- なお、この例は推奨実装ではなく信頼境界の問いを示すためのものです。*呼び出し側が申告した* client IP は監査注記の材料であってアクセス判断の材料ではありません。ポリシーが依拠する IP は、ボディではなくトランスポート（デプロイが信頼するプロキシヘッダを `context.headers` から読む Collector）から取得してください。

## RuleCollector を書くタイミング

`RuleCollector` は `CollectorContext` を `Rule[]` に変換するファクトリです。組み込み例として [`packages/builtins/src/rules/collectors/`](../packages/builtins/src/rules/collectors/) の `ResourceActionPermissionRuleCollector` / `ResourceActionScopeRuleCollector` があります。リクエストの resource と action から `HasPermission` / `HasScope` を構築しています。

Rule の構築がリクエスト時のコンテキスト（resource、action、ヘッダ）に依存する場合に、カスタム `RuleCollector` を書いてください。Rule が全リクエストで一定なら、compose 時に `Rule` を直接インスタンス化すれば十分で、Collector は不要です。

### Rule は `attrs` だけで判断する

RuleCollector は `CollectorContext` 全体を見られるため、エンジンのレイヤ分離をうっかり壊せる唯一の場所です。契約（[AGENTS.md — Collector / Rule / Attribute Contract](../AGENTS.md#collector--rule--attribute-contract)）は「Rule の判断は attribute だけから導出できること」です。リクエストを読むのは Collector、`attrs` を読むのが Rule です。

境界線は builtins が示しています。`ResourceActionScopeRuleCollector` は `new HasScope(\`${context.action}:${context.resource.resourceType}\`)` を組み立てます — リクエスト由来ではありますが、それは Rule が *探す値* にすぎず、判断の対象は `attrs.get(ATTR_SCOPES)` です。違反はもう一方の形です: Collector 内で context を unwrap し、そこで 2 つの値を比較し、`verify(attrs)` が `attrs` を無視して既に済ませた比較結果を返す Rule を生成する。この Rule は attribute からはテストできず、閉じ込めたリクエスト状態は Collector を一度も通っていません — その一部でも `readUntrustedRequestContext` 由来なら、呼び出し側のデータが attribute 層を経ずに判断へ到達したことになります。

成立していなければならない性質は、`verify(attrs)` が `attrs` の決定的かつ副作用のない関数であることです — 評価器が最初の失敗で止まらず全グループを実行できるのは、この性質があるからです。Rule が *探す値* を collect 時に固定することはこれを壊しませんが、context を保持して *verify 時に読む* ことは壊します。

**そしてこれは今や規約であるだけでなく検査でもあります。** 決め手となるテストは「Rule を collect し、context を捨て、`verify(attrs)` を呼ぶ — 答えが変わらないこと」です。[`tests/integration/src/conformance/rulePurity.mts`](../tests/integration/src/conformance/rulePurity.mts) の `describeRulePurityConformance` がまさにこれを実行します: revoke 可能な context ビュー経由で Rule を collect し、revoke してから再び問う。context を保持した Rule はアクセス時に throw し、値をコピーしただけの Rule は throw しません。自作の RuleCollector もこれに通してください。（CI も `verify` の本体に `ctx.` / `context.` がないか grep しますが、それは分かりやすい形に対する backstop であり、実際に判定するのは conformance suite です。）

答えを焼き込んでしまった Rule の直し方は次のとおりです: *検査される側の値* は `attrs.get(...)` から取得し、*それが照合される相手の値* はリクエストから捕捉したままでよい — ただし context への live な参照ではなく、コピーされた値として。

## 関連資料

- [`@o3co/auth.policy-verifier.core` README](../packages/core/README.ja.md) — インターフェース、評価器、パイプライン。
- [`@o3co/auth.policy-verifier.builtins` README](../packages/builtins/README.ja.md) — 組み込み Rule / Collector のリファレンス。
- [AGENTS.md — Core Vocabulary Scope](../AGENTS.md#core-vocabulary-scope) — `builtins` が汎用 `requestContext` Collector を提供しない理由。
