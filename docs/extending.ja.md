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
  verify(attrs: Attributes): boolean;
}
```

- `verify(attrs)` は述語です。通過時に `true`、失敗時に `false` を返します。**safe-deny 規約:** 欠落・型不一致・不正な属性は `false` を返してください。例外を投げない。例外を投げるとポリシー失敗がエラー応答になり、評価状態が漏れます。
- `ruleType` は評価器が Rule をグループ化するのに使います。同じ `ruleType` の Rule は OR 結合されます（いずれか 1 つ通ればグループ通過）。異なる `ruleType` の Rule はグループ間 AND 結合されます（全グループ通過が必要）。**既定の `ruleType` は、暗黙の衝突を避けるためにルール設定を十分にエンコードしてください。** 例えば `AttrLiteralEqual` は `attr_literal_equal:${a}:${typeof v}:${String(v)}` を使います — `typeof v` セグメントは `v=true` と `v="true"` が同じ `ruleType` に畳み込まれて意図に反して OR 結合されるのを防ぎます。
- `code` は短く安定した識別子（例: `"no_permission"`、`"attr_not_equal"`）で、下流のプログラム的ハンドリングに適した文字列にしてください。
- `message` は人間可読な denial メッセージです。有益な情報を載せつつ、機微な属性値は漏らさないこと。

### 実例: `UserLevelAtLeast`

`userLevel` が設定値以上の数値のときに通過する Rule:

```ts
import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";

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

  verify(attrs: Attributes): boolean {
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

## カスタム AttributeCollector の書き方

`AttributeCollector` は `@o3co/auth.policy-verifier.core` で定義されます:

```ts
interface AttributeCollector {
  collect(context: CollectorContext): Promise<Attributes>;
}
```

- 1 つの Collector は **焦点を絞った属性キー群**を生成してください。関係のない抽出をまとめないこと。IP アドレスと User-Agent を抽出するなら Collector を 2 つに分けてください。
- 属性キーは文字列定数を使うこと。`@o3co/auth.policy-verifier.core` の `ATTR_SCOPES`、`ATTR_PERMISSIONS`、`ATTR_ROLES`、`ATTR_USER_ID`、`ATTR_CLIENT_ID` を参照。プロジェクト固有のキーは独自の定数を定義し、**core のキーを異なるセマンティクスで再利用しないこと**。
- `AttributePipeline` は全 Collector を並列実行し、結果をマージします: 配列値は連結、スカラ／オブジェクトは後勝ち。この挙動に合わせて設計し、Collector の実行順序には依存しないこと。
- `CollectorContext.requestContext` は意図的に型付けされていません。エンジンは汎用 `requestContext` Collector を提供しません。`requestContext` の形は consuming project のトランスポート層 / interceptor が定義するものであり、解釈はプロジェクトの責務だからです。必要なフィールドごとに焦点を絞った Collector を書き、形の検証はその Collector 内で行ってください。

### 実例: `ClientIpCollector`

`requestContext` から IP アドレスを属性として抽出する Collector:

```ts
import type {
  AttributeCollector,
  Attributes,
  CollectorContext,
} from "@o3co/auth.policy-verifier.core";

// プロジェクト固有の属性キー定数 — プロジェクトローカルで定義する。
export const ATTR_CLIENT_IP = "clientIp" as const;

export class ClientIpCollector implements AttributeCollector {
  async collect(context: CollectorContext): Promise<Attributes> {
    const ip = context.requestContext?.clientIp;
    if (typeof ip !== "string" || ip.length === 0) {
      return new Map(); // 何も出力しない — 下流 Rule では属性欠落として safe-deny される
    }
    return new Map([[ATTR_CLIENT_IP, ip]]);
  }
}
```

要点:

- 形が不正または値が欠落している場合は空 `Map` を返すこと。キーを `null` / `undefined` に設定しない — 「欠落」と「存在するが falsy」を区別する下流 Rule が壊れやすくなるため。
- 形の検証は Collector 内で行う。`requestContext` は `Record<string, unknown>` 型なので、それを消費する Collector が narrowing の適切な場所です。

## RuleCollector を書くタイミング

`RuleCollector` は `CollectorContext` を `Rule[]` に変換するファクトリです。組み込み例として [`packages/builtins/src/rules/collectors/`](../packages/builtins/src/rules/collectors/) の `ResourceActionPermissionRuleCollector` / `ResourceActionScopeRuleCollector` があります。リクエストの resource と action から `HasPermission` / `HasScope` を構築しています。

Rule の構築がリクエスト時のコンテキスト（resource、action、ヘッダ）に依存する場合に、カスタム `RuleCollector` を書いてください。Rule が全リクエストで一定なら、compose 時に `Rule` を直接インスタンス化すれば十分で、Collector は不要です。

## 関連資料

- [`@o3co/auth.policy-verifier.core` README](../packages/core/README.ja.md) — インターフェース、評価器、パイプライン。
- [`@o3co/auth.policy-verifier.builtins` README](../packages/builtins/README.ja.md) — 組み込み Rule / Collector のリファレンス。
- [AGENTS.md — Core Vocabulary Scope](../AGENTS.md#core-vocabulary-scope) — `builtins` が汎用 `requestContext` Collector を提供しない理由。
