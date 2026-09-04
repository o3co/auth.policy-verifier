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

- **Collectors** (`AttributeCollector`, `RuleCollector`) are the only layer that reads `CollectorContext`. They transform the raw request into static outputs: attributes or rules. They are also the only layer that does I/O, which is why they are the only layer with deadlines — see `packages/core/src/collectorLimits.mts` and the `signal` note below.
- **Attributes** are plain values (`Map<string, unknown>`). Once produced by collectors, they carry no reference to the originating request.
- **Rules** are predicates over attributes (`verify(attrs): boolean`). `verify` must be a **deterministic, side-effect-free function of `attrs`**: equal attributes give equal answers, and it must not mutate its input, perform I/O, or observe anything the engine cannot see. `verify` is handed a `ReadonlyAttributes` (`ReadonlyMap<string, unknown>`), so the "must not mutate" half is a compile error rather than a request.

This contract guarantees that rules are pure functions of attributes: testable in isolation, cacheable, and free from hidden coupling to request shape. It is also what `evaluate()` spends when it runs every rule group instead of stopping at the first failure.

**What a rule may do.** A rule **may** hold values fixed at collect time — *what it looks for*. `ResourceActionScopeRuleCollector` computes `` `${context.action}:${context.resource.resourceType}` `` while the request is in hand and passes the resulting string to `new HasScope(...)`. The comparand is request-derived and that is fine: it is fixed once, and `HasScope.verify` remains a function of `attrs`.

**What a rule must not do.** A rule **must not** retain `CollectorContext`, or any live reference into it, and read it inside `verify`. The answer would then depend on request state the engine cannot observe, which breaks isolation testing, caching, and the guarantee `evaluate()` relies on. The two shapes look alike — both mention `context.action` in the collector — which is precisely why the difference is spelled out rather than left to taste.

**The deciding test:** collect the rule, discard the context, then call `verify(attrs)`. The answer must be unchanged. A rule that copied a string out at collect time answers identically; a rule that kept the request cannot answer at all.

That test is executable, not rhetorical. `describeRulePurityConformance` in [`tests/integration/src/conformance/rulePurity.mts`](tests/integration/src/conformance/rulePurity.mts) collects the rules through a revocable view of the context, revokes it, and re-runs `verify` — so a rule holding the request throws on the access, and one holding a copied value does not. Apply it to every rule collector you add. `.github/workflows/ci.yml` also greps `verify` bodies for context reads, but that is a backstop for the obvious shape; the conformance suite is the check.

**`CollectorContext.signal` is on the same side of the line as everything else.** It is the one field a collector is *meant* to hold live — it is a cancellation handle, and passing it to `fetch` is what it is for — but that licence ends when `collect` returns. `aborted` moves on its own, so a rule holding a signal and reading it inside `verify` is not a function of `attrs` at all, and the suite revokes it exactly as it revokes `ctx.resource`. What the suite could not do is wrap it in a `Proxy`: `AbortSignal`'s members are brand-checked against the receiver, so a proxied signal fails `addEventListener`, `AbortSignal.any` and `fetch` — the harness would have started failing honest collectors for an artefact of its own. So the view is a real signal minted by `AbortSignal.any`, and revoking shadows its members with accessors that throw the same error a revoked proxy does. The check is unchanged in strength; only the mechanism differs, for the one type that cannot be a proxy. The reasoning is written on `revocableSignal`; a future field with internal slots of its own should follow it rather than take an exemption.

## Core Vocabulary Scope

`packages/core` intentionally exports a narrow vocabulary, and its input shape is engine-neutral.

**Core consumes `(subject-attribute-bag, resource, action, requestContext)`.** `CollectorContext.subject` is a `SubjectAttributes` — `{ readonly [key: string]: unknown }` — and core neither names nor reads any field of it (#170). The engine can therefore receive a subject however a deployment authenticates one; it is what makes "drop-in replaceable with OPA or Cedar" true of the core layer and not just of the wire.

**The default server populates the bag from verified JWT claims.** That mapping lives at one edge — `createTokenAuthenticator` in `packages/server/src/jwt/tokenAuthenticator.mts` spreads the signature-verified claims into the bag (plus `authScheme`) — so under this server the bag's keys are the token's claims, and the claim vocabulary belongs to the layers on either side of core: the server writes it, the builtins collectors narrow it back out. The builtin mapping from claims to attribute keys (`core/src/keys.mts`):

| JWT claim | Read by | Attribute key |
| --- | --- | --- |
| `sub` | `PayloadSubjectIdCollector` (builtins) | `ATTR_USER_ID` |
| `azp` | `PayloadSubjectIdCollector` (builtins) | `ATTR_CLIENT_ID` |
| `scope` | `PayloadScopeCollector`, `ResourceActionScopeRuleCollector` (builtins) | `ATTR_SCOPES` |

`iss` / `aud` / `exp` / `iat` are enforced inside the authenticator before the bag is built and are read by nothing downstream. `KeyResolver` / `KeyResolverFactory` are server types for the same reason: token-credential plumbing, not engine vocabulary.

- `ATTR_*` constants are restricted to well-known OAuth 2.0 / OIDC and RBAC concepts: scopes, permissions, roles, subject user id, client id. These are concepts every consumer of the ABAC engine shares, and they originate from transport-neutral standards (not tied to a specific interceptor or wire format). The constants name attributes, not claims — the claim reading happens in builtins, per the table above.
- Domain-specific attribute keys (business identifiers, tenant flags, protocol-specific fields) **must not** be added to core. They belong to the consuming service, which declares its own constants and reads/writes the same `Attributes` map.
- Core **does not** assume a shape for `CollectorContext.requestContext`. This field is a free-form container whose contents are defined by the interceptor/transport layer of each consuming project. Core provides only the hook — consumers provide the interpretation via their own `AttributeCollector` implementations. It is also the only caller-controlled input on the context, so its type is the opaque `UntrustedRequestContext`: reading it takes an explicit `readUntrustedRequestContext(...)`. See [docs/extending.md — The trust boundary](docs/extending.md#the-trust-boundary-requestcontext-is-the-callers).

When tempted to add a new `ATTR_*`, a named field on `SubjectAttributes`, or a built-in collector that reads a specific `requestContext` key, stop and ask:

- Is this concept universal across every service using the engine (JWT/OIDC/RBAC standards)? If yes, the *attribute constant* can live in core — the claim it is derived from is still read in builtins, and `SubjectAttributes` stays fieldless either way.
- Is it a particular consumer's vocabulary, or tied to a specific interceptor's payload shape? If yes, the constant and its collector belong to that consuming service.

### Writing Project-Specific Attribute Collectors

Consuming projects wire their interceptor's `requestContext` into attributes by implementing focused collectors, one per field they care about (or grouped logically). A collector should:

1. Read exactly the fields it intends to promote.
2. Validate the shape of each value (type, non-empty, format) — `requestContext` is unvalidated free-form data, supplied by the caller.
3. Write into the `Attributes` map under the project's own constant keys.
4. **Reserve those keys**, at module scope beside the constants:
   `reserveAttributeKeys({ owner, keys, reason })`. The reserved set is a registry core exposes, not a list core enumerates — core cannot see a package's vocabulary, so each package reserves its own, and `RequestContextAttributeCollector` refuses an operator mapping onto any of them. Module scope is what makes the ordering hold: a composition can only name your collectors by importing your module, so the keys are registered before any collector is constructed. `packages/cedar` reserves its four `request*` keys this way.

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

**The invariant:** the same configuration gets the same verdict at **both** boundaries — accepted by both, or refused by both naming the same key in the same words. That is the thing that must hold, and it is a statement about answers, not about code.

**The mechanism:** **one shared check function**, imported by each side. Not two implementations agreeing on a constant — one function, so that what is accepted, what a missing key defaults to, and how a refusal is worded have a single definition and cannot drift apart. The schema turns its verdict into a zod issue at the operator's path; the guard throws it, naming the caller and the path. This is the default and what to reach for: the invariant is only ever as safe as the thing guaranteeing it, and a shared function guarantees it structurally rather than by vigilance.

**Why both.** A hand-built config bypasses the schema entirely, so without the guard `createApp` would accept what a config file cannot, and the invariant would be advice. And a check duplicated rather than shared is worse than it looks: the two drift, and the drift is silent — the same configuration written two ways, answered two ways, with nothing failing to say so.

**"Must not get a different answer" is the deciding formulation, not decoration.** It was the explicit tiebreaker for the `previousSecrets` `null` contract (#147): `null` is refused rather than read as "no rotation configured" — diverging from auth.provider's own precedent — because `AppConfigSchema` types the field `z.array(...).optional()` and rejects `null` before `checkHs256Rotation` is ever reached. Accepting it in the guard would have handed a hand-built config a different answer from a parsed one. The full reasoning is written on `checkHs256Rotation`.

**What breaking it cost.** The numeric knobs were the family that shared only *constants*: the schema read each through its own `z.coerce.number().int()…` chain, the runtime through an ad-hoc `??` or `Number(…)`. #157 found seven values the two genuinely disagreed on. `oauth.jwt.jwksCooldownMs = false` meant `0` through the schema — refetch on every miss, the fetch storm the knob exists to prevent — and a boot failure through the resolver. `verify.maxBatchSize = null` was refused at boot by the schema, while `createVerifyRouter`'s `?? DEFAULT` silently applied a 50-entry cap. Nobody wrote either behaviour; both fell out of one knob having two readers. The full table is in the #157 entry of [`CHANGELOG.md`](CHANGELOG.md). This rule is written down because breaking it produced real divergence, not because it is tidy.

**The worked examples**, all under `packages/server/src`:

- `checkJwksUri` ([`jwt/jwks.mts`](packages/server/src/jwt/jwks.mts)) — the JWKS transport policy (#109). Returns a result; the schema renders it as a zod issue, and `parseJwksUri` throws the same message for the `KeyResolverFactory`.
- `checkHs256Rotation` ([`jwt/hs256Rotation.mts`](packages/server/src/jwt/hs256Rotation.mts)) — the HS256 rotation shape, and the entropy floor over every secret in it (#112, #114). Collects every issue with its path, so both boundaries report a block with two mistakes in one round trip.
- `resolveBound` ([`config/bounds.mts`](packages/server/src/config/bounds.mts)) — every numeric knob (#157). One spec table carries each knob's default, range and unit; a boundary supplies only the config path it saw the key at.

All three are dependency-free on purpose, and that is what makes the shared function possible rather than a coincidence: `AppConfigSchema` imports them, so anything they reached back for would arrive in every config-only consumer of the schema. `jwt/tokenAuthenticator.mts` brings jose with it and `routes/verify.mts` brings express — a check living beside either could not be shared with the schema at all. So write the check function first, somewhere the config layer can import, and only then call it from both sides.

**The deciding test:** write the same configuration twice — once as a config file through `AppConfigSchema`, once as an object handed straight to `createApp` or `createVerifyRouter`. Both must accept it, or both must refuse it and name the same key in the same words. The test is on the verdicts, not on how they are produced, which is why it still applies wherever the mechanism has had to be given up.

So reach for the shared function first; and if you have given it up, you owe the departure clause below. An invariant with two readers and nothing holding them together is not enforced twice, it is implemented twice — which is precisely the state the numeric knobs were in before #157.

**When a departure is legitimate.** Only when the two boundaries genuinely cannot read one shape — not when sharing would merely be inconvenient. The burden then shifts rather than lifting: name the departure at both sites, word the refusals alike, and put something in place of the shared function that holds the two implementations in step. A test asserting that both boundaries answer the same way on the same input is the minimum. The invariant is unchanged; only the thing guaranteeing it is weaker, which is the whole reason a departure has to be argued for.

`assertVerifyRouterJwtConfig` (`jwt/tokenAuthenticator.mts`) is the worked example. It and the schema's `superRefine` enforce the same two invariants — RFC 9068 `iss`/`aud`/`typ` presence, and consent to decode-only mode — as separate implementations, because #134 split the spellings: on the wire the consent is the single key `oauth.jwt.mode = "insecure-decode"`, while internally it stays the two-key `validate: false` + `allowInsecureDecode: true` interlock. There is no one shape for a shared function to read.

**What discharges the burden is [`packages/server/src/__tests__/jwtConfigTwoBoundaryParity.test.mts`](packages/server/src/__tests__/jwtConfigTwoBoundaryParity.test.mts) (#164).** One table; each row is one configuration written twice, in each boundary's own spelling, asserting that both reach the same verdict and that a refusal names the same key. It is the deciding test above, executed. A new invariant on either side is a row there, not a new test — and the per-side suites stay: `tokenAuthenticator.test.mts` pins the exact drift the pre-#132 `createApp` copy had (a bare falsy check that accepted `issuer: []` and never looked at `tokenType`), while only the table pins the *agreement*.

Two things the table settled on its first run, and both are the reason a departure has to be argued for rather than assumed harmless:

- **It found a divergence nobody had noticed.** `tokenType: ["at+jwt"]` was refused by the schema and accepted by the guard, whose one presence check was shared across `issuer`, `audience` and `tokenType` and so admitted a list for a header that is a single value. The hand-built config booted and then rejected *every* token, misreported as an infrastructure outage. Fixed in #164; the guard now checks `tokenType` as a string. Two implementations kept in step by hand had drifted, exactly as #157's numeric knobs had — which is the whole argument for preferring the shared function.
- **The `tokenType` default is the one carve-out**, below.

**Defaults are part of the verdict.** A default that only one boundary applies makes the two disagree as surely as a range does, which is why `resolveBound` carries each knob's `fallback` and `createApp` spells out `mode ?? "verify"`. Adding a default means mirroring it at the other boundary, or earning a carve-out here.

**The one carve-out: `oauth.jwt.tokenType`'s absence** — the accepted `typ` header, not any field on the decoded payload. The schema defaults it to `at+jwt`; `assertVerifyRouterJwtConfig` requires it. So a config file that omits the key boots, and a hand-built config that omits it is refused. That is deliberate, and it stays, because closing it in either direction costs more than the symmetry buys:

- *Defaulting in the guard* would have it supply a security-relevant value the caller never wrote — the opposite of a guard whose stated job is to fail fast on a config whose static types cannot be trusted.
- *Requiring it in the schema* would break every deployed config file that omits the key, for no gain. `at+jwt` is the RFC 9068 value, it is applied before any token is seen, and no parsed config is ever left without a `typ` pin.
- The two boundaries are not disagreeing about the **value** — both end with a verifying config that pins `typ`. They disagree about **who supplies it**: the wire has a default an operator may rely on, and `VerifyingJwtConfig` declares `tokenType: string` required, so the API boundary's static contract already asks the caller for it and the guard is only catching a JavaScript caller who ignored the type. The side without the default is the fail-closed one.

The carve-out is a row in the parity table like every other row, asserting the documented asymmetry rather than skipping it, and the table asserts there is exactly one such row. Closing it later therefore fails the test and sends the author back to this paragraph. **This is the only carve-out**; a second one is a sign the departure has drifted, not that the rule has an exception.

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
