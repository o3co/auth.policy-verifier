# create-o3co-policy-verifier

auth.policy-verifier 用の CLI スキャフォルダーです。組み込みテンプレートから新しいスタンドアロンサーバープロジェクトを生成します。

## 使い方

```sh
npx create-o3co-policy-verifier <project-name>
```

スキャフォルダーはカレントディレクトリに `<project-name>` という名前のディレクトリを作成し、次のステップを表示します。

```
cd <project-name>
npm install
npm run debug
```

## 処理内容

1. `<project-name>` を npm パッケージ名のルールに従って検証する（下記参照）。
2. `templates/standalone/` をターゲットディレクトリにコピーする（`node_modules/` と `dist/` は除外）。
3. `package.json` を書き換える: `name` を `<project-name>` に設定し、`private` を削除し、`workspace:*` の依存バージョンを `templates/versions.json` に記録された公開済み semver に置き換える。
4. 次のステップを表示する。

## バリデーションルール

- `^[a-z0-9][a-z0-9-._~]*$` に一致すること（有効なスコープなし npm パッケージ名）
- 最大 214 文字
- `.` または `..` であってはならない
- ターゲットディレクトリが既に存在してはならない

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
