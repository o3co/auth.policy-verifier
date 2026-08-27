# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version sections follow the release labeling policy in
[`docs/release-policy.md`](docs/release-policy.md).

## [Unreleased]

### Changed

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
  `createApp` for hand-built config objects) with a migration message:
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
