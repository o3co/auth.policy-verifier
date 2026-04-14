# create-o3co-policy-verifier

CLI scaffolder for auth.policy-verifier. Generates a new standalone server project from the built-in template.

## Usage

```sh
npx create-o3co-policy-verifier <project-name>
```

The scaffolder creates a directory named `<project-name>` in the current working directory, then prints next-step instructions:

```
cd <project-name>
npm install
npm run debug
```

## What It Does

1. Validates `<project-name>` against npm package name rules (see below).
2. Copies `templates/standalone/` to the target directory, excluding `node_modules/` and `dist/`.
3. Rewrites `package.json`: sets `name` to `<project-name>`, removes `private`, and replaces `workspace:*` dependency versions with the published semver versions from `templates/versions.json`.
4. Prints next-step instructions.

## Validation Rules

- Must match `^[a-z0-9][a-z0-9-._~]*$` (valid unscoped npm package name)
- Maximum 214 characters
- Must not be `.` or `..`
- Target directory must not already exist

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
import { scaffold, main } from "create-o3co-policy-verifier";
```

| Export | Signature | Description |
|---|---|---|
| `scaffold` | `(targetDir: string, projectName: string): void` | Copies the template and rewrites `package.json` |
| `main` | `(): void` | CLI entry point — parses `process.argv` and calls `scaffold` |

## See Also

- [`@o3co/auth-policy-verifier-standalone`](../templates/standalone) — the template that this tool generates
- [`@o3co/auth.policy-verifier.server`](../packages/server) — Express app factory used by the generated project
