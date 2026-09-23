# @o3co/create-auth-policy-verifier

Last updated: 2026-09-23

CLI scaffolder for auth.policy-verifier. Generates a new standalone server project from the built-in template.

## Responsibility

**Role.** The `npm create` / `npx` entry point that turns the in-repo template
[`templates/standalone`](../templates/standalone) into a new, independent project.
It runs once, on the operator's machine; nothing in the generated project imports
it, and it imports none of the `packages/*` libraries.

**Owns.** Project-name and directory validation, copying the template, rewriting
the generated `package.json` (name, `workspace:*` → published versions), and the
one-time `pnpm-lock.yaml` resolution.

**Does not own.** The content of the generated project — source, config, Dockerfile,
tests — which is the template's (edit `templates/standalone`, not this package).
Runtime behaviour belongs to `@o3co/auth.policy-verifier.server` and the libraries
the template depends on.

**Why a separate package.** It is published on its own with a `bin`, so it can be
run with `npx` without installing the verifier. Its build step
([`scripts/copy-templates.mjs`](scripts/copy-templates.mjs)) embeds a copy of the
template and the current library versions (`templates/versions.json`), and inlines
`tsconfig.base.json` into the template's `tsconfig.json`, because the monorepo
tree is not present in the published tarball.

## Usage

```sh
npx @o3co/create-auth-policy-verifier <project-name> [--dir <dir-name>] [--no-lockfile]
```

`<project-name>` may be either a scoped npm name (`@scope/pkg`) or an unscoped name (`pkg`).

Unscoped example:

```sh
npx @o3co/create-auth-policy-verifier my-verifier
cd my-verifier
pnpm install
pnpm run debug
```

Scoped example (directory defaults to the package portion):

```sh
npx @o3co/create-auth-policy-verifier @my-org/auth.policy-verifier
cd auth.policy-verifier
pnpm install
pnpm run debug
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
5. Rewrites `package.json`: sets `name` to `<project-name>` verbatim (scope-preserving), keeps `"private": true` on purpose (#126: a scaffolded authorization service should not be publishable by accident — remove the field yourself if you really intend to publish), and replaces each `workspace:*` dependency version with `^<version>` from `templates/versions.json`.
6. Resolves that dependency set into `pnpm-lock.yaml` (`pnpm install --lockfile-only --ignore-workspace`), unless `--no-lockfile` was passed.
7. Prints next-step instructions.

### The generated `pnpm-lock.yaml`

The template's `Dockerfile` installs with `pnpm install --frozen-lockfile`, so
the generated project needs a lockfile to build at all. It cannot ship with the
template: until step 5 has replaced every `workspace:*` with a published
version, the dependency set the lockfile would have to pin does not exist. So
it is resolved once, here, against the rewritten `package.json`. **Commit it** —
it is what makes `docker build` reproducible.

Step 6 needs `pnpm` (or `corepack`) and a reachable registry, and neither is
guaranteed on the machine running the scaffolder. It is therefore best-effort:
on failure the scaffold still succeeds and prints what to do, because the
generated project is perfectly usable without a lockfile — it just cannot be
built into an image until `pnpm install` has been run once. Pass
`--no-lockfile` to skip the step outright (offline scaffolding, or a pipeline
that installs later anyway).

## Validation Rules

`<project-name>` must match one of:

- Unscoped: `^[a-z0-9][a-z0-9-._~]*$`
- Scoped: `^@[a-z0-9][a-z0-9-._~]*/[a-z0-9][a-z0-9-._~]*$`

Both forms must be non-empty, not `.` or `..`, and ≤ 214 characters.

`--dir <value>` must match the unscoped pattern above (same constraints).

## Known Limitations

The bundled template's `README.md` / `README.ja.md` still carry the upstream title `@o3co/auth-policy-verifier-standalone`. When generating a scoped project, that title will not match your `package.json` name; edit it manually if it matters for your use case.

## Generated Structure

The generated project is the whole of [`templates/standalone`](../templates/standalone)
— every file and directory, including dotfiles, tests and the template's own READMEs —
except `node_modules/` and `dist/` (`EXCLUDED_DIRS` in [`src/index.mts`](src/index.mts)).
The files that differ from the in-repo template are `tsconfig.json` (the base config
is inlined into it when the scaffolder is built), `package.json` (step 5) and the
newly resolved `pnpm-lock.yaml` (step 6; commit it). See the template's README for
what each file does.

## Programmatic API

The scaffolder also exports its internals for programmatic use:

```ts
import { scaffold, main } from "@o3co/create-auth-policy-verifier";
```

| Export | Signature | Description |
|---|---|---|
| `scaffold` | `(targetDir: string, projectName: string): void` | Copies the template and rewrites `package.json` |
| `generateLockfile` | `(targetDir: string): LockfileResult` | Resolves `pnpm-lock.yaml` in an already-scaffolded directory; reports failure rather than throwing |
| `main` | `(): void` | CLI entry point — parses `process.argv`, calls `scaffold`, then `generateLockfile` |

## See Also

- [`@o3co/auth-policy-verifier-standalone`](../templates/standalone) — the template that this tool generates
- [`@o3co/auth.policy-verifier.server`](../packages/server) — Express app factory used by the generated project
