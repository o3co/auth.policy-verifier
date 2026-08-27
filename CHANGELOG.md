# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version sections follow the release labeling policy in
[`docs/release-policy.md`](docs/release-policy.md).

## [Unreleased]

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
