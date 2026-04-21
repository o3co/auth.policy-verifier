# create-o3co-policy-verifier

auth.policy-verifier 用の CLI スキャフォルダーです。組み込みテンプレートから新しいスタンドアロンサーバープロジェクトを生成します。

## 使い方

```sh
npx create-o3co-policy-verifier <project-name> [--dir <dir-name>]
```

`<project-name>` はスコープ付き npm 名 (`@scope/pkg`) とスコープなしの名前 (`pkg`) のどちらでも指定できます。

スコープなしの例:

```sh
npx create-o3co-policy-verifier my-verifier
cd my-verifier
npm install
npm run debug
```

スコープ付きの例（ディレクトリ名はパッケージ部分がデフォルト）:

```sh
npx create-o3co-policy-verifier @my-org/auth.policy-verifier
cd auth.policy-verifier
npm install
npm run debug
```

`--dir` でディレクトリ名を明示指定:

```sh
npx create-o3co-policy-verifier @my-org/auth.policy-verifier --dir verifier
cd verifier
```

## 処理内容

1. `<project-name>` を検証する（バリデーションルール参照）。
2. 生成先ディレクトリ名を決定する: `--dir <value>` が指定されていればその値、そうでなければスコープ付き名のパッケージ部分、最終的には入力値そのもの。
3. 生成先ディレクトリがすでに存在する場合はエラーを出力して終了する。
4. `templates/standalone/` を生成先ディレクトリにコピーする（`node_modules/` と `dist/` は除外）。
5. `package.json` を書き換える: `name` を `<project-name>` をそのまま設定し（スコープを保持）、`private` を削除し、`workspace:*` のバージョン参照を `templates/versions.json` の公開 semver バージョンに置き換える。
6. 次のステップの手順を表示する。

## バリデーションルール

`<project-name>` は以下のいずれかに一致する必要があります:

- スコープなし: `^[a-z0-9][a-z0-9-._~]*$`
- スコープ付き: `^@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*$`

いずれも空文字・`.`・`..` は不可、最大 214 文字。

`--dir <value>` はスコープなしのパターンと同じ制約です。

## 既知の制約

内包されているテンプレートの `README.md` / `README.ja.md` の見出しは `@o3co/auth-policy-verifier-standalone` のままです。スコープ付きでプロジェクトを生成した場合、この見出しは生成された `package.json` の `name` と一致しません。必要に応じて手動で修正してください。

## 生成される構造

```
<project-name>/
├── config/
│   └── application.conf    # HOCON 設定ファイル（環境変数で上書き可）
├── src/
│   └── main.mts            # コンポジションルート — 設定を読み込みサーバーを起動する
├── Dockerfile
├── Makefile
├── docker-compose.yml
├── docker-compose.test.yml
├── package.json
└── tsconfig.json
```

## プログラム API

スキャフォルダーは内部実装をエクスポートしており、プログラムから利用できます。

```ts
import { scaffold, main } from "create-o3co-policy-verifier";
```

| エクスポート | シグネチャ | 説明 |
|---|---|---|
| `scaffold` | `(targetDir: string, projectName: string): void` | テンプレートをコピーして `package.json` を書き換える |
| `main` | `(): void` | CLI エントリポイント — `process.argv` を解析して `scaffold` を呼び出す |

## 関連

- [`@o3co/auth-policy-verifier-standalone`](../templates/standalone) — このツールが生成するテンプレート
- [`@o3co/auth.policy-verifier.server`](../packages/server) — 生成されたプロジェクトが使用する Express アプリファクトリ
