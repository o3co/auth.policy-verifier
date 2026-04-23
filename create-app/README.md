# @o3co/create-auth-policy-verifier

CLI scaffolder for auth.policy-verifier. Generates a new standalone server project from the built-in template.

## Usage

```sh
npx @o3co/create-auth-policy-verifier <project-name> [--dir <dir-name>]
```

`<project-name>` may be either a scoped npm name (`@scope/pkg`) or an unscoped name (`pkg`).

Unscoped example:

```sh
npx @o3co/create-auth-policy-verifier my-verifier
cd my-verifier
npm install
npm run debug
```

Scoped example (directory defaults to the package portion):

```sh
npx @o3co/create-auth-policy-verifier @my-org/auth.policy-verifier
cd auth.policy-verifier
npm install
npm run debug
```

Override the directory name with `--dir`:

```sh
npx @o3co/create-auth-policy-verifier @my-org/auth.policy-verifier --dir verifier
cd verifier
```

## What It Does

1. Validates `<project-name>` (see Validation Rules).
2. Derives the target directory name: `--dir <value>` if given, else the unscoped part of a scoped name, else the name itself.
3. Aborts with an error if the target directory already exists.
4. Copies `templates/standalone/` to the target directory, excluding `node_modules/` and `dist/`.
5. Rewrites `package.json`: sets `name` to `<project-name>` verbatim (scope-preserving), removes `private`, and replaces `workspace:*` dependency versions with published semver versions from `templates/versions.json`.
6. Prints next-step instructions.

## Validation Rules

`<project-name>` must match one of:

- Unscoped: `^[a-z0-9][a-z0-9-._~]*$`
- Scoped: `^@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*$`

Both forms must be non-empty, not `.` or `..`, and ≤ 214 characters.

`--dir <value>` must match the unscoped pattern above (same constraints).

## Known Limitations

The bundled template's `README.md` / `README.ja.md` still carry the upstream title `@o3co/auth-policy-verifier-standalone`. When generating a scoped project, that title will not match your `package.json` name; edit it manually if it matters for your use case.

## Generated Structure

```
<project-name>/
├── config/
│   └── application.conf    # HOCON config (env var overrides)
├── src/
│   └── main.mts            # Composition root — loads config and starts server
├── Dockerfile
├── Makefile
├── docker-compose.yml
├── docker-compose.test.yml
├── package.json
└── tsconfig.json
```

## Programmatic API

The scaffolder also exports its internals for programmatic use:

```ts
import { scaffold, main } from "@o3co/create-auth-policy-verifier";
```

| Export | Signature | Description |
|---|---|---|
| `scaffold` | `(targetDir: string, projectName: string): void` | Copies the template and rewrites `package.json` |
| `main` | `(): void` | CLI entry point — parses `process.argv` and calls `scaffold` |

## See Also

- [`@o3co/auth-policy-verifier-standalone`](../templates/standalone) — the template that this tool generates
- [`@o3co/auth.policy-verifier.server`](../packages/server) — Express app factory used by the generated project
