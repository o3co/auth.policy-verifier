# Project Guidelines

## Language

- All source code, comments, variable names, function names, test descriptions, and commit messages must be written in **English only**.
- Responses to the user may be in any language.

## Development Process

- All feature work and bug fixes **must** follow TDD (Test-Driven Development).
- Write the failing test first. Watch it fail. Then write the minimal code to make it pass.
- Never write production code without a failing test that demands it.
- If code was written before its test, delete it and start over from the test.
- When generating implementation plans, every task must include explicit RED → GREEN → REFACTOR steps.

## Collector / Rule / Attribute Contract

The engine enforces a strict separation between the context-reading layer and the context-free layer.

- **Collectors** (`AttributeCollector`, `RuleCollector`) are the only layer that reads `CollectorContext`. They transform the raw request into static outputs: attributes or rules.
- **Attributes** are plain values (`Map<string, unknown>`). Once produced by collectors, they carry no reference to the originating request.
- **Rules** are predicates over attributes (`verify(attrs): boolean`). `verify` must be a **deterministic, side-effect-free function of `attrs`**: equal attributes give equal answers, and it must not mutate its input, perform I/O, or observe anything the engine cannot see. `verify` is handed a `ReadonlyAttributes` (`ReadonlyMap<string, unknown>`), so the "must not mutate" half is a compile error rather than a request.

This contract guarantees that rules are pure functions of attributes: testable in isolation, cacheable, and free from hidden coupling to request shape. It is also what `evaluate()` spends when it runs every rule group instead of stopping at the first failure.

**What a rule may do.** A rule **may** hold values fixed at collect time — *what it looks for*. `ResourceActionScopeRuleCollector` computes `` `${context.action}:${context.resource.resourceType}` `` while the request is in hand and passes the resulting string to `new HasScope(...)`. The comparand is request-derived and that is fine: it is fixed once, and `HasScope.verify` remains a function of `attrs`.

**What a rule must not do.** A rule **must not** retain `CollectorContext`, or any live reference into it, and read it inside `verify`. The answer would then depend on request state the engine cannot observe, which breaks isolation testing, caching, and the guarantee `evaluate()` relies on. The two shapes look alike — both mention `context.action` in the collector — which is precisely why the difference is spelled out rather than left to taste.

**The deciding test:** collect the rule, discard the context, then call `verify(attrs)`. The answer must be unchanged. A rule that copied a string out at collect time answers identically; a rule that kept the request cannot answer at all.

That test is executable, not rhetorical. `describeRulePurityConformance` in [`tests/integration/src/conformance/rulePurity.mts`](tests/integration/src/conformance/rulePurity.mts) collects the rules through a revocable view of the context, revokes it, and re-runs `verify` — so a rule holding the request throws on the access, and one holding a copied value does not. Apply it to every rule collector you add. `.github/workflows/ci.yml` also greps `verify` bodies for context reads, but that is a backstop for the obvious shape; the conformance suite is the check.

## Core Vocabulary Scope

`packages/core` intentionally exports a narrow vocabulary.

- `ATTR_*` constants are restricted to well-known OAuth 2.0 / OIDC and RBAC concepts: scopes, permissions, roles, subject user id (JWT `sub`), client id (JWT `azp`). These are concepts every consumer of the ABAC engine shares, and they originate from transport-neutral standards (not tied to a specific interceptor or wire format).
- Domain-specific attribute keys (business identifiers, tenant flags, protocol-specific fields) **must not** be added to core. They belong to the consuming service, which declares its own constants and reads/writes the same `Attributes` map.
- Core **does not** assume a shape for `CollectorContext.requestContext`. This field is a free-form container whose contents are defined by the interceptor/transport layer of each consuming project. Core provides only the hook — consumers provide the interpretation via their own `AttributeCollector` implementations. It is also the only caller-controlled input on the context, so its type is the opaque `UntrustedRequestContext`: reading it takes an explicit `readUntrustedRequestContext(...)`. See [docs/extending.md — The trust boundary](docs/extending.md#the-trust-boundary-requestcontext-is-the-callers).

When tempted to add a new `ATTR_*` or a built-in collector that reads a specific `requestContext` key, stop and ask:

- Is this concept universal across every service using the engine (JWT/OIDC/RBAC standards)? If yes, it can live in core.
- Is it a particular consumer's vocabulary, or tied to a specific interceptor's payload shape? If yes, the constant and its collector belong to that consuming service.

### Writing Project-Specific Attribute Collectors

Consuming projects wire their interceptor's `requestContext` into attributes by implementing focused collectors, one per field they care about (or grouped logically). A collector should:

1. Read exactly the fields it intends to promote.
2. Validate the shape of each value (type, non-empty, format) — `requestContext` is unvalidated free-form data, supplied by the caller.
3. Write into the `Attributes` map under the project's own constant keys.

```typescript
// project-side: collectors/SubscriberDidCollector.mts
import type { AttributeCollector, Attributes, CollectorContext } from "@o3co/auth.policy-verifier.core";
import { readUntrustedRequestContext } from "@o3co/auth.policy-verifier.core";

export const ATTR_SUBSCRIBER_DID = "subscriberDid" as const;

export class SubscriberDidCollector implements AttributeCollector {
  async collect(context: CollectorContext): Promise<Attributes> {
    const attrs: Attributes = new Map();
    const v = readUntrustedRequestContext(context.requestContext)?.subscriber_did;
    if (typeof v === "string" && v.length > 0) {
      attrs.set(ATTR_SUBSCRIBER_DID, v);
    }
    return attrs;
  }
}
```

The rule then reads `attrs.get(ATTR_SUBSCRIBER_DID)` without ever touching `CollectorContext`.

## Two-Boundary Config Validation

`packages/server` takes its configuration two ways, and both have to reach the same verdict.

- **`AppConfigSchema`** ([`packages/server/src/config/application.schema.mts`](packages/server/src/config/application.schema.mts)) parses config files. It runs at boot and reports every issue at once, at the path the operator wrote.
- **The runtime guards** — `createApp`, the `KeyResolverFactory` implementations, `createVerifyRouter` — serve the hand-built config objects those entry points also accept. A library consumer reaches them with the schema never having run, and the TypeScript shapes are not a defence: a JavaScript caller ignores them, and a config assembled from `process.env` arrives as strings.

**The rule:** a wire invariant is enforced at **both** boundaries, through **one shared check function**. Not two implementations agreeing on a constant — one function, imported by each side. The schema turns its verdict into a zod issue at the operator's path; the guard throws it, naming the caller and the path. What is accepted, what a missing key defaults to, and how a refusal is worded all come from that one function.

**Why both.** A hand-built config bypasses the schema entirely, so without the guard `createApp` would accept what a config file cannot, and the invariant would be advice. And a check duplicated rather than shared is worse than it looks: the two drift, and the drift is silent — the same configuration written two ways, answered two ways, with nothing failing to say so.

**"Must not get a different answer" is the deciding formulation, not decoration.** It was the explicit tiebreaker for the `previousSecrets` `null` contract (#147): `null` is refused rather than read as "no rotation configured" — diverging from auth.provider's own precedent — because `AppConfigSchema` types the field `z.array(...).optional()` and rejects `null` before `checkHs256Rotation` is ever reached. Accepting it in the guard would have handed a hand-built config a different answer from a parsed one. The full reasoning is written on `checkHs256Rotation`.

**What breaking it cost.** The numeric knobs were the family that shared only *constants*: the schema read each through its own `z.coerce.number().int()…` chain, the runtime through an ad-hoc `??` or `Number(…)`. #157 found seven values the two genuinely disagreed on. `oauth.jwt.jwksCooldownMs = false` meant `0` through the schema — refetch on every miss, the fetch storm the knob exists to prevent — and a boot failure through the resolver. `verify.maxBatchSize = null` was refused at boot by the schema, while `createVerifyRouter`'s `?? DEFAULT` silently applied a 50-entry cap. Nobody wrote either behaviour; both fell out of one knob having two readers. The full table is in the #157 entry of [`CHANGELOG.md`](CHANGELOG.md). This rule is written down because breaking it produced real divergence, not because it is tidy.

**The worked examples**, all under `packages/server/src`:

- `checkJwksUri` ([`jwt/jwks.mts`](packages/server/src/jwt/jwks.mts)) — the JWKS transport policy (#109). Returns a result; the schema renders it as a zod issue, and `parseJwksUri` throws the same message for the `KeyResolverFactory`.
- `checkHs256Rotation` ([`jwt/hs256Rotation.mts`](packages/server/src/jwt/hs256Rotation.mts)) — the HS256 rotation shape, and the entropy floor over every secret in it (#112, #114). Collects every issue with its path, so both boundaries report a block with two mistakes in one round trip.
- `resolveBound` ([`config/bounds.mts`](packages/server/src/config/bounds.mts)) — every numeric knob (#157). One spec table carries each knob's default, range and unit; a boundary supplies only the config path it saw the key at.

All three are dependency-free on purpose, and that is part of the rule rather than a coincidence: `AppConfigSchema` imports them, so anything they reached back for would arrive in every config-only consumer of the schema. `jwt/tokenAuthenticator.mts` brings jose with it and `routes/verify.mts` brings express — a check living beside either could not be shared with the schema at all. So write the check function first, somewhere the config layer can import, and only then call it from both sides.

**The deciding test:** write the same configuration twice — once as a config file through `AppConfigSchema`, once as an object handed straight to `createApp` or `createVerifyRouter`. Both must accept it, or both must refuse it and name the same key in the same words. If you cannot point at the single function that decides, the invariant is not enforced twice; it is implemented twice.

**Two known departures**, both deliberate, and to be matched rather than copied:

- `assertVerifyRouterJwtConfig` (`jwt/tokenAuthenticator.mts`) and the schema's `superRefine` enforce the same two invariants — RFC 9068 `iss`/`aud`/`typ` presence, and consent to decode-only mode — as separate implementations, because #134 split the spellings. On the wire the consent is the single key `oauth.jwt.mode = "insecure-decode"`; internally it stays the two-key `validate: false` + `allowInsecureDecode: true` interlock. There is no one shape for a shared function to read, so the two are kept in step by hand and their messages worded alike.
- A default that only one boundary applies is a divergence of the same kind, which is why `resolveBound` carries each knob's `fallback` and `createApp` spells out `mode ?? "verify"`. The exception is `oauth.jwt.tokenType`: the schema defaults it to `at+jwt` while `assertVerifyRouterJwtConfig` requires it outright, because `VerifyingJwtConfig` declares it required and the API boundary's static contract therefore already asks the caller for it. Adding a default means mirroring it at the other boundary, or writing down why not.

## Release Process

Releases are triggered by pushing a `v*` tag to GitHub. There is no manual publish step; `.github/workflows/release.yml` handles the rest.

### Flow

1. Cut the CHANGELOG: rename `## [Unreleased]` to `## [0.2.1] - YYYY-MM-DD` and commit (see `docs/release-policy.md` R2/R6 for the full pre-tag audit)
2. Create and push a version tag on that commit: `git tag v0.2.1 && git push origin v0.2.1`
3. GitHub Actions (`release.yml`) is triggered by the `v*` tag push
4. The workflow checks the tag shape and that `CHANGELOG.md` has a section for it, rewrites every package's `package.json` `version` to match the tag (via `pnpm -r exec pnpm version`), builds, typechecks, tests, then runs `pnpm -r publish --access public --provenance` across the monorepo
5. A GitHub Release is published with auto-generated notes

### Implications

- **All packages share a single version** derived from the tag. Do not set per-package versions in `package.json` manually; the workflow overwrites them.
- **`package.json` `version` is effectively a placeholder** (`0.0.0`). It exists because npm requires the field, but the real version comes from the tag at publish time.
- **The published set is four packages**: `@o3co/auth.policy-verifier.core`, `.builtins`, `.server` and `@o3co/create-auth-policy-verifier`. `templates/standalone` and `tests/integration` are `private: true` and are stamped with the version but never published.
- **Idempotent re-runs, per package:** `pnpm -r publish` skips each package that is already on the registry at this version and publishes the rest. Rerunning a tag after a publish that failed partway through therefore publishes exactly the packages that are missing — there is no whole-job "already published" short-circuit, and re-adding one would make a partial publish unrecoverable (see the comment in `release.yml`).
- **The CHANGELOG must be cut before the tag.** The workflow refuses to publish a tag whose version has no `## [X.Y.Z]` section in `CHANGELOG.md`.
- **Tag format must be `v` + a SemVer 2.0.0 version**, prerelease identifiers included (`v1.2.3`, `v1.2.3-rc.1`, `v1.2.3-rc-1`, `v1.2.3-0.3.7`). SemVer build metadata (`v1.2.3+build.5`) is rejected on purpose: npm ignores it for version precedence, so two such tags are one npm version, and the CHANGELOG heading the tag must match would not be the version consumers see. The workflow strips the `v` when computing the npm version — that one parse is the only one, and the later steps consume its output rather than re-deriving it from `GITHUB_REF`.

### For Agents / Contributors

When asked to "release 0.2.1" or similar:

1. Ensure all changes are merged to `main` (releases are cut from `main`, not feature branches)
2. Verify the change set warrants the requested version bump (breaking change → major, feature → minor, fix → patch)
3. Run the release-cut audit in `docs/release-policy.md` R6 and land the CHANGELOG rename (`## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD`) first — the workflow refuses a tag whose version has no CHANGELOG section
4. Propose the tag command to the user; do not push tags without explicit user approval (tag push is irreversible from an npm-publish perspective once the workflow succeeds)
5. After the tag is pushed, watch the Actions run: `gh run watch` or `gh run list --workflow=release.yml`

Do not edit `package.json` `version` fields as part of a release PR — the workflow handles versioning.

## Module Resolution

Each package uses Node.js [subpath imports](https://nodejs.org/api/packages.html#subpath-imports) with a conditional `development` / `default` mapping:

```json
"imports": {
  "#/*": {
    "development": "./src/*",
    "default": "./dist/*"
  }
}
```

- **Tests (vitest):** Vite 8+ includes `"development|production"` in its default resolve conditions. During `vitest run`, `isProduction=false` causes it to expand to `"development"`, resolving `#/*` to `./src/*`. This is an implicit dependency on Vite's resolver — Node.js does not enable the `development` condition natively.
- **Published packages:** Consumers resolve `#/*` via the `"default"` condition to `./dist/*`.
- **Local dev server:** The standalone template uses `NODE_OPTIONS='--conditions=development'` to explicitly activate the condition.
- **Cross-package references** (e.g., `builtins` importing from `core`) go through `exports`, which always point to `./dist/`. Run `pnpm -r run build` before running tests in downstream packages.

### Build vs. typecheck

Each package has two TypeScript configs, and the split exists because of the point above:

- `tsconfig.json` — what `build` emits. It excludes `src/**/__tests__/**`. A compiled test in `dist/` would be published (`files: ["dist", …]`), and it would carry the `#/` specifiers that only test files use — which resolve through the package's own `imports` map to `./src/*` under the `development` condition, a path no tarball ships. CI's `publish-readiness` job asserts against both, on the tarball.
- `tsconfig.typecheck.json` — what `typecheck` checks (`tsc --noEmit`). It re-includes `src/**/*`, tests included, and emits nothing.

So `pnpm run typecheck` is the only thing that type-checks test files; `pnpm run build` no longer does. Both run in `ci.yml` and `release.yml`. `tests/integration` has no build at all, so its `typecheck` is a plain `tsc --noEmit` against its own already-`noEmit` config.

A test file must therefore never be imported by shipped source — the build cannot see it.
