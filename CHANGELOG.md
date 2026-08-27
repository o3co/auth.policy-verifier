# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version sections follow the release labeling policy in
[`docs/release-policy.md`](docs/release-policy.md).

## [Unreleased]

### Security

- **BREAKING**: `oauth.jwt.jwksUri` must now be an `https://` URL
  ([#109](https://github.com/o3co/auth.policy-verifier/issues/109)). Plaintext
  `http://` is accepted **only** for loopback hosts — `localhost`,
  `127.0.0.0/8`, `[::1]` — and every other scheme (`file:`, `ftp:`, …) is
  refused outright. A URI that fails the check is rejected at config-parse
  time, so the deployment fails at boot instead of at the first request that
  misses the key cache. The built-in RS256/ES256/EdDSA key resolvers repeat the
  check when they build the key set, so a hand-built config that never went
  through `AppConfigSchema` still fails inside `createApp` rather than serving.

  Rationale: every key the JWKS endpoint serves can verify tokens the
  deployment accepts, so the endpoint's identity is the entire trust anchor and
  TLS server authentication is what establishes it. Over plaintext, anyone on
  the network path (or holding a DNS answer) substitutes their own signing key
  and mints tokens that verify — a full authorization bypass. A loopback
  address has no network path to sit on, which is why the development carve-out
  is safe; a host reached by container or DNS name is not loopback.

  Operator migration — a config that boots today and stops booting after this
  release is one with a routable plaintext JWKS URI, e.g. the
  `http://auth-provider:3000/.well-known/jwks.json` the README used to
  recommend. Either:
  - put a TLS terminator in front of the provider and switch the URI to
    `https://` (the README's `Connecting to auth.provider` section now shows
    this), or
  - drop the JWKS entirely and hand the verifier the provider's public key
    directly with `oauth.jwt.publicKey` / `publicKeyPath`, or
  - if the provider genuinely runs on the same host, address it as
    `http://127.0.0.1:<port>/...` rather than by service name.

  The error names the key and the rejected value:
  `jwksUri must use https; http is accepted only for loopback hosts
  (localhost, 127.0.0.0/8, [::1]), got "http://auth-provider:3000/..."`.
- **BREAKING**: `http.hostname` now defaults to `127.0.0.1` instead of `0.0.0.0`
  ([#108](https://github.com/o3co/auth.policy-verifier/issues/108)). `/verify`
  answers with an authorization decision, so a port anyone can route to is a
  decision oracle — a probe of which tokens, scopes and resources a deployment
  accepts, and an unauthenticated compute sink while it is at it. The subject
  JWT establishes who a decision is *about*, never which service supplied
  `resource` / `action` / `context`. The sidecar deployment this project targets
  needs loopback only, so binding every interface is now an opt-in.

  **Operator migration** — a deployment that must be reachable from another host
  or container has to say so explicitly, or it will start refusing connections
  it used to accept:

  - HOCON: `http.hostname = "0.0.0.0"`
  - Env: `HTTP_HOSTNAME=0.0.0.0`
  - Docker/Kubernetes: **every** containerised deployment needs this — inside a
    container, loopback means reachable from nothing, so a published port or
    Service simply never connects. The standalone template's
    `docker-compose.yml` now sets `HTTP_HOSTNAME=0.0.0.0` for exactly this reason.
  - A deployment already pinning `http.hostname` (in `application.conf`, an env
    overlay, or `HTTP_HOSTNAME`) is unaffected.
  - Pair the opt-in with `http.callerAuth.token` below: past the loopback
    boundary, anyone who can reach the port can ask for decisions. `createApp`
    logs `unauthenticated_non_loopback_bind` at warn when it sees a non-loopback
    bind with no caller authentication configured.

### Added

- Bounds on the remote JWKS fetch, which happens inside a verify request
  whenever key resolution misses the cache
  ([#109](https://github.com/o3co/auth.policy-verifier/issues/109)):
  `oauth.jwt.jwksTimeoutMs` (default `5000`), `oauth.jwt.jwksCooldownMs`
  (default `30000`) and `oauth.jwt.jwksCacheMaxAgeMs` (default `600000`), with
  the matching `OAUTH_JWT_JWKS_TIMEOUT_MS` / `_COOLDOWN_MS` /
  `_CACHE_MAX_AGE_MS` env overrides in the standalone template. The defaults
  match what jose applied implicitly, so timing is unchanged; they are now
  stated (a jose release cannot silently retune the decision hot path) and
  tunable per deployment. Each must be a whole number of milliseconds —
  positive, or non-negative for the cooldown, where `0` means "refetch on every
  miss". `AppConfigSchema` validates them at config-parse time; the key
  resolver validates them again when it builds the key set, coercing the string
  form a HOCON env substitution (or a hand-built config assembled from
  `process.env`) delivers, so an unparsed value can no longer reach jose and be
  silently ignored in favour of its default. `@o3co/auth.policy-verifier.server`
  additionally exports `checkJwksUri`, `parseJwksUri` and
  `resolveJwksFetchBounds` for custom `KeyResolverFactory` implementations that
  fetch their own JWKS.
- Optional caller authentication for the decision endpoints
  ([#108](https://github.com/o3co/auth.policy-verifier/issues/108)). Setting
  `http.callerAuth.token` (env `HTTP_CALLER_AUTH_TOKEN`) makes `POST /verify`
  and `POST /verify/batch` require that shared credential from the calling
  service, in addition to the subject bearer token they already require.

  - The credential travels in `http.callerAuth.header` — default
    `x-caller-token` (env `HTTP_CALLER_AUTH_HEADER`), deliberately not
    `Authorization`, which carries the subject token. The two answer different
    questions: who a decision is about, versus which service may ask for one.
  - Compared in constant time, before the request body is parsed and before any
    collector pipeline runs, so an unauthenticated peer costs the process
    nothing. A missing credential and a wrong one get the identical `401`, body
    `{ "decision": "deny", "code": "caller_unauthenticated", "message": "Caller authentication failed" }`
    — the rejection must not tell a prober whether their guess had the right
    shape. Rejections log `caller_auth_rejected` at warn.
  - `GET /healthcheck` is never gated: an orchestrator probe has no credential
    to present, and it reveals nothing a decision does.
  - **Optional in this release** and off unless configured, so existing
    deployments (and container-to-container callers such as the cross-repo E2E)
    keep working. An empty `HTTP_CALLER_AUTH_TOKEN=` is rejected at boot rather
    than read as "disabled". Making it mandatory later is a one-line change to
    `CALLER_AUTH_REQUIRED` in `@o3co/auth.policy-verifier.server`'s
    `config/defaults` — see that constant's doc comment.
  - A shared credential is a floor, not a ceiling: it does not replace network
    policy or mTLS between the enforcement layer and this service.

### Changed

- **BREAKING**: `DotNotationResourceParser`
  (`@o3co/auth.policy-verifier.builtins`) now validates a canonical grammar and
  refuses what it used to repair
  ([#117](https://github.com/o3co/auth.policy-verifier/issues/117)). The derived
  `resourceType` is the authorization namespace —
  `ResourceActionScopeRuleCollector` turns it into the `{action}:{resourceType}`
  scope that must be granted — so two distinct resources that parsed to the same
  type were authorized identically, and a caller could reach resource A through a
  grant written for resource B. This is [#116](https://github.com/o3co/auth.policy-verifier/issues/116)'s
  principle applied one layer earlier: stop silently rewriting authorization
  identifiers, on the resource side as well as the scope side.

  The accepted grammar:

  ```text
  resource = segment *( "." segment )
  segment  = type [ ":" id ]
  type     = 1*tchar
  id       = 1*tchar
  tchar    = %x21 / %x23-2D / %x2F-39 / %x3B-5B / %x5D-7E
             ; RFC 6749 NQCHAR less "." and ":"
             ; i.e. printable ASCII except space, `"`, `\`, "." and ":"
  ```

  - **Separator preserved**: `resourceType` is now the segment types joined with
    `.` instead of `_`. `"project:1.member:2"` derives `project.member`, not
    `project_member`. The old join collapsed the nested type `a.b` and the flat
    type literally named `a_b` onto one string; `.` is now reserved as the
    separator and cannot occur inside a type, so distinct type sequences produce
    distinct types. `_` is an ordinary type character.
  - **Empty segments refused**: `""`, `a..b`, `.a`, `a.`, `a:` and `:1` now
    throw. `a..b` used to parse, landing in whatever namespace the empty types
    produced.
  - **Extra `:` components refused, not truncated**: `a:1:2` used to be read as
    `a:1` with the tail silently dropped, widening a deliberately narrowed
    identifier. It now throws.
  - **Whitespace refused, not trimmed**: `"  project:1  "` and `"project : 1"`
    now throw. Trimming made them one resource for scope rules while
    `ResourceActionPermissionRuleCollector`, which reads `raw`, still saw two.
  - Characters outside the grammar (non-ASCII, `"`, `\`, control characters) are
    refused: a type that cannot appear in an OAuth scope value is a type no
    issuer could grant.
  - **Migration** — a deployment whose config or callers name resources whose
    derived types collide under the old join must rename one side before
    upgrading, because the two now authorize separately:
    - Scope grants and policy referring to a nested type must be rewritten from
      `<action>:a_b` to `<action>:a.b`. A grant of `read:project_member` no
      longer authorizes the resource `project:1.member:2`; that resource now
      requires `read:project.member`. A resource whose type is genuinely the
      single flat segment `project_member` is unaffected.
    - Resource strings sent by callers must be canonical: no surrounding or
      inner whitespace, no empty segments, at most one `:` per segment. A caller
      that was sending `"project : 1"` and relying on the trim must send
      `"project:1"`.
    - An id that needs `.` or `:` must be encoded (percent-encoding round-trips
      through the grammar) or handled by a `ResourceParser` written for that
      syntax.
  - New `ResourceParseError` exported from `@o3co/auth.policy-verifier.core`,
    carrying the refused string (`raw`) and the reason (`detail`). Any
    `ResourceParser` should raise it for input outside its syntax.
  - `POST /verify` and `POST /verify/batch` answer **400 `invalid_request`** for
    a `resource` the parser refuses — the caller's syntax error, not a server
    fault — instead of 500, and no longer log it as `verify_internal_error`, so
    a client looping on a typo cannot manufacture an incident. The batch
    endpoint validates every entry's resource before deciding any of them, and
    names the offending index. Any other throw from a parser still surfaces as
    500.
- **BREAKING**: `HasScope` (`@o3co/auth.policy-verifier.builtins`) now matches
  scopes exactly instead of normalizing them
  ([#116](https://github.com/o3co/auth.policy-verifier/issues/116)). The old
  matcher lowercased both sides, rewrote a bare granted scope to `read:<scope>`,
  and destructured on `:` so that everything after the second segment was
  dropped — each of which could satisfy a requirement the issuer never granted.
  OAuth 2.0 scope values are case-sensitive opaque strings (RFC 6749 §3.3).
  - **Case**: matching is now case-sensitive. `read:PROJECT` no longer satisfies
    a `read:project` requirement (old: matched → new: denied).
  - **Multi-colon**: a scope is no longer split at `:`. `read:project:restricted`
    no longer satisfies `read:project` (old: matched, silently widening a
    deliberately narrowed grant → new: denied), and `read:project:restricted`
    now satisfies its own identical requirement (old: never matched, because the
    granted value was truncated to `read:project` before comparison → new:
    matched).
  - **Bare-scope rewrite**: a granted scope containing no `:` is now compared
    literally. It is no longer rewritten to `read:<scope>` unless the new
    `allowBareScopeRewrite` option is explicitly enabled (default `false`).
    Even when enabled, only a scope with no `:` is rewritten — a value such as
    `project:restricted` is never re-interpreted.
  - **Migration** — a deployment whose issuer emits bare resource names
    (`project` rather than `read:project`) must opt back in, or every such token
    starts being denied:
    - HOCON: `{ collector = "ResourceActionScopeRuleCollector", allowBareScopeRewrite = true }`
    - TypeScript: `new ResourceActionScopeRuleCollector({ allowBareScopeRewrite: true })`
      or `new HasScope(scope, { allowBareScopeRewrite: true })`
    - A deployment whose issuer emits `{action}:{resourceType}` scopes in the
      exact case the policy requires needs no change.
  - A non-string entry in `ATTR_SCOPES` now denies instead of throwing a
    `TypeError` (which surfaced as a 500 rather than a decision).
- **BREAKING**: the `reason` payload of `POST /verify` and `POST /verify/batch`
  responses (and the `RuleGroupOutcome` type in
  `@o3co/auth.policy-verifier.core`) now reports each rule group honestly
  ([#135](https://github.com/o3co/auth.policy-verifier/issues/135)). The old
  `rules` field meant two different things — every alternative on a failing
  group, but only the single passing rule on a passing group — so a consumer
  aggregating "rules evaluated" miscounted.
  - `reason.groups[].rules` is **renamed to `reason.groups[].evaluated`** and
    now always means the same thing: every rule the group actually ran, in
    evaluation order. On a failing group the content is unchanged (every
    alternative ran and is listed). On a passing group it now also includes the
    alternatives that were tried and failed *before* the passing rule, followed
    by the passing rule itself; alternatives after the passing rule never ran
    and are still not listed.
  - **New `reason.groups[].satisfiedBy`**, present exactly on passing groups:
    the rule that satisfied the group — always the last element of `evaluated`.
    Failing groups carry no `satisfiedBy`.
  - Migration for consumers of the wire contract:
    - "which rule satisfied a passing group" — read `group.satisfiedBy`
      (previously `group.rules[0]`).
    - "which alternatives failed in a failing group" — read `group.evaluated`
      (previously `group.rules`).
    - "how many rules ran" — `group.evaluated.length` is now exact; the old
      `rules` undercounted passing groups that tried failing alternatives
      first.
  - Unchanged: the group-level `passed` flag, evaluation-order listing of
    `reason.groups`, and the deny `code` / `message` (still the first
    alternative of the first failing group).
- **BREAKING**: the wire-config pair `oauth.jwt.validate` (boolean) and
  `oauth.jwt.allowInsecureDecode` was folded into a single enum
  `oauth.jwt.mode = "verify" | "insecure-decode"`, defaulting to `"verify"`
  ([#134](https://github.com/o3co/auth.policy-verifier/issues/134)).

  | Before | After |
  |---|---|
  | `validate = true` (default) | `mode = "verify"` (default) |
  | `validate = false` + `allowInsecureDecode = true` | `mode = "insecure-decode"` |
  | `validate = false` alone (refused to boot) | not expressible — the mode string itself is the consent |

  Configs still carrying the removed keys fail at parse time (and at
  `createApp` for hand-built config objects) with a migration message, exported
  from `@o3co/auth.policy-verifier.server` as `JWT_MODE_MIGRATION_MESSAGE`:
  `oauth.jwt.validate/allowInsecureDecode were replaced by oauth.jwt.mode; set
  mode = "verify" or the explicit "insecure-decode"`.

  The standalone template's env override `OAUTH_JWT_VALIDATE` (and
  `OAUTH_JWT_ALLOW_INSECURE_DECODE`) was replaced by `OAUTH_JWT_MODE`.

  Rationale: after #131, `validate = false` still enforced `exp`/`nbf`, so the
  key no longer named what it gates. The value `"insecure-decode"` is
  self-documenting consent — an accidental env-var flip can produce a stray
  boolean, but never that literal string — preserving the intent of the #106
  double opt-in in a single explicit knob. The internal router-facing
  discriminated union (`validate: true` / `validate: false` +
  `allowInsecureDecode: true`) is unchanged; only the wire config and the
  wire-to-internal mapping changed. Decode-only deployments still boot with the
  `jwt_validation_disabled` event logged at error level.

- The release workflow no longer gates the whole publish on one package
  ([#120](https://github.com/o3co/auth.policy-verifier/issues/120)). It used to
  ask npm whether `@o3co/auth.policy-verifier.core` was already at the tag's
  version and, if so, skip publishing entirely. Publishing this workspace is
  four independent registry writes — `.core`, `.builtins`, `.server` and
  `@o3co/create-auth-policy-verifier` — so a run that published core and then
  failed on another package left that version half-released, and every retag
  from then on hit the gate, did nothing, and never published the missing
  packages. `pnpm -r publish` already skips per package what is already on the
  registry, so the gate is now gone: rerunning a tag publishes exactly the
  packages that are missing. `auth.provider` removed the same gate for the same
  reason in [o3co/auth.provider#111](https://github.com/o3co/auth.provider/pull/111).

  The workflow also now refuses a tag that is not `v` + a SemVer version, or
  whose version has no `## [X.Y.Z]` section in this file, before it builds or
  publishes anything — the CHANGELOG cut required by
  [`docs/release-policy.md`](docs/release-policy.md) R2/R6 is now checked rather
  than assumed. Prerelease tags are accepted in full SemVer form
  (`v1.2.3-rc.1`, `v1.2.3-rc-1`, `v1.2.3-0.3.7`); build metadata
  (`v1.2.3+build.5`) is refused, because npm ignores `+…` when comparing
  versions and two such tags would be one registry version.