# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version sections follow the release labeling policy in
[`docs/release-policy.md`](docs/release-policy.md).

## [Unreleased]

### Security

- `HasPermission` no longer lets the two halves of a single-wildcard grant
  overlap in the required permission
  ([#180](https://github.com/o3co/auth.policy-verifier/issues/180)).

  `required.startsWith(prefix) && required.endsWith(suffix)` had nothing
  stopping the halves from sharing characters, so a grant of `posts.*.read`
  matched a required permission of `posts.read` — the single `.` satisfied both
  checks at once. That is an over-grant, and it contradicted the rule's own
  contract ("the literal halves around the `*` still compare exactly"). The
  guard is one length check: each character of the required permission counts
  toward at most one half, while the wildcard itself may still match the empty
  string.

  From the same audit: malformed permission and role data never matches and
  never throws — the discipline `HasScope` already applies to non-string scope
  values. A non-array value under either attribute key, a role whose
  `permissions` is missing or not an array, and non-string entries are all
  ignored rather than half-honoured — notably, a bare string under
  `permissions` is no longer spread into characters. Before, one bad row from
  a store-backed role collector threw inside `verify` and surfaced as a 500
  deny.

- `POST /verify/batch` decides its entries in bounded lanes, at most
  `verify.batchConcurrency` at a time (default 8, new knob)
  ([#183](https://github.com/o3co/auth.policy-verifier/issues/183)).

  The collector concurrency cap (#115) is per pipeline, **per decision** — it
  never bounded the batch. The batch route started every entry under a bare
  `Promise.all`, so one request at the default `maxBatchSize` of 50 could hold
  50 × 8 collectors in flight per pipeline: for a store-backed collector
  deployment, ~800 simultaneous outbound calls from a single authenticated
  HTTP request, past any per-request rate limit in front of `/verify`. The
  per-request ceiling is now the stated product of the two caps — 8 × 8, not
  50 × 8 — and answers still come back in request order. The knob is read
  through `resolveBound` at both config boundaries like every other numeric
  knob, and the comment on `DEFAULT_COLLECTOR_CONCURRENCY` no longer claims
  the per-decision cap protects the batch.

### Fixed

- The millisecond knobs are bounded above by what a timer can hold
  ([#181](https://github.com/o3co/auth.policy-verifier/issues/181)).

  `verify.collectorTimeoutMs`, `verify.collectorDeadlineMs` and
  `oauth.jwt.jwksTimeoutMs` had a floor and no ceiling. Node stores a
  `setTimeout` delay in a signed 32-bit integer and silently clamps anything
  above 2 147 483 647 to ~1 ms — so a validated value became a ~1 ms budget,
  and every decision denied with `collector_timeout` (or every JWKS fetch
  aborted). Fail-closed, so availability rather than an authorization hole,
  but exactly the failure the two-boundary doctrine exists to prevent: *"a
  value must be refused rather than passed to a library that quietly applies
  its own default."* All three now carry `maximum: MAX_TIMER_MS` (exported
  from core) at both config boundaries, and core's own
  `resolveCollectorLimits` refuses the same ceiling for a hand-built pipeline
  that never met a config boundary.

## [0.4.0] - 2026-08-29

### Security

- **BREAKING**: collectors now run under a deadline, a cancellation signal and a
  concurrency bound, and **a bound that trips denies the decision**
  ([#115](https://github.com/o3co/auth.policy-verifier/issues/115)).

  Both pipelines ran their collectors under a bare `Promise.all`. Collectors are
  the layer designed to call databases and HTTP APIs, and a `Promise.all` has no
  deadline, no cancellation and no bound on how much work it starts — so a
  single collector holding a dead socket held the authorization decision with
  it, for as long as the socket took to notice. Siblings kept running after one
  of them had already failed the request, and a dependency slowdown piled up
  unbounded in-flight work instead of shedding it. On a PDP's hot path that is
  both a latency failure and a DoS amplifier: one `POST /verify/batch` is up to
  50 decisions, each fanning out across every configured collector.

  **`CollectorContext` gained a required `signal: AbortSignal`** — the breaking
  half. It aborts when that collector overruns its budget, when the pipeline
  overruns its deadline, when a sibling has already failed the decision, or when
  the caller went away.

  *What a collector author must change:* nothing to keep compiling — a collector
  only reads the context. What you should change is to pass the signal to
  whatever the collector waits on, which is the only thing that makes
  cancellation real:

  ```diff
  -const res = await fetch(this.endpoint);
  +const res = await fetch(this.endpoint, { signal: context.signal });
  ```

  The pipeline stops waiting on a collector that ignores its signal — the bound
  does not depend on cooperation — but that collector's outbound call goes on
  running against a dependency that has already lost the request it belonged to.

  *What breaks* is code that **builds** a `CollectorContext`: a custom
  transport or interceptor, and every test fixture with a context literal. Add
  the field. A transport that has no cancellation of its own passes
  `new AbortController().signal`. Callers of `AttributePipeline.collect` /
  `RulePipeline.collect` are unaffected: those now take a `CollectorRequest` —
  the same shape *without* `signal`, since the per-collector signal is the
  pipeline's to mint. A caller with an outer deadline may still set the optional
  `signal` on the request, and the pipeline links it into its own, so aborting
  it cancels every collector in flight.

  **The bounds, and why these numbers.** All three are on by default, so a
  library consumer who configures nothing is still bounded:

  | Knob | Default | What it bounds |
  | --- | --- | --- |
  | `verify.collectorTimeoutMs` | `2000` | one collector. A healthy lookup against a dependency the deployment runs answers in single-digit milliseconds; 2s is far past "slow" and short of the timeouts callers put on `/verify` itself, so the verifier is the layer that notices — and it can name *which* collector, which a caller-side timeout never can. The budget starts when that collector starts, so queueing behind the concurrency cap does not spend it |
  | `verify.collectorDeadlineMs` | `5000` | the whole fan-out, per pipeline. A per-collector budget cannot bound a *set*: once collectors queue, enough of them each finishing just inside their own budget still adds up to a request nobody is waiting for |
  | `verify.collectorConcurrency` | `8` | collectors in flight at once, per pipeline, per decision. More than any realistic collector set, so a normal configuration still fans out in one wave and nothing about its latency changes. What it removes is the tail — dozens of collectors, or a 50-entry batch, multiplying into simultaneous outbound calls against a dependency that has just started to slow down |

  Each knob routes through `resolveBound` at both config boundaries — the schema
  for config files, `createApp` for the hand-built configs it also accepts —
  with one spec table in `config/bounds.mts`, per AGENTS.md "Two-Boundary Config
  Validation". The defaults themselves are `packages/core`'s and are re-exported
  by `config/defaults.mts` rather than restated, so the config file's default and
  the pipeline's cannot drift. `0` is refused for all three: a zero timeout
  cancels every collector before it can answer, and a zero concurrency is a
  fan-out that starts nothing and resolves with no attributes and no rules — a
  fail-open dressed as a setting. The shipped `templates/standalone` config
  writes all three out with their `VERIFY_COLLECTOR_*` env substitutions, beside
  the `#118` limits.

  **A note on the `verify` block's own default, because this nearly went wrong.**
  The block carries a `.default(() => ({…}))`, and zod takes that object
  *verbatim* — it never parses it back through the shape. A knob added to the
  shape but not to that literal is therefore `undefined` for every config that
  omits the `verify` block entirely, which is the ordinary deployment shape,
  since an overlay config repeats only the sections it changes. Nothing throws;
  the bound simply stops existing. #115 and #118 both added knobs here and landed
  a day apart, so the second merge could have looked clean and silently dropped
  the first's defaults. It is now asserted instead of reviewed: the two
  productions of the block — present-and-empty (which runs the shape's per-key
  defaults) and absent (which takes the literal) — must be deeply equal, so a
  future knob added to one and not the other fails without anyone remembering to
  extend a list. `loadConfig.test.mts` proves the same end-to-end through the
  real HOCON loader, on a config directory with no `verify` block at all.

  **A collector whose decision is already lost is never invoked.** Not started
  and then cancelled — not started. Handing a collector an aborted signal and
  relying on it to notice is a different thing: the documented way to use the
  signal is to pass it to `fetch`, so a collector that does not check
  `signal.aborted` before its first `await` has already put the request on the
  wire. That is an outbound call for an answer nobody will read, usually against
  the very dependency whose slowness ended the decision. The check sits at the
  point of invocation rather than in the loop above it, so it holds however the
  fan-out is driven, and the failure it raises is the *set's* reason — the
  deadline, a sibling's error, the caller leaving — never a timeout attributed to
  a collector that never ran and never overran anything.

  **Fail closed: a timeout denies, and can never allow.** The pipeline throws
  `CollectorTimeoutError` and returns nothing at all — never the results that
  arrived in time. That is the whole design decision. Partial attributes merely
  weaken a rule's inputs, but partial rules weaken the *policy*, and an empty
  rule set is an **allow** wherever `rule.onEmptyRuleSet = "allow"` is set. So
  the evaluator is never reached: `routes/verify.mts` catches the error and
  builds the deny itself — `403`, `code: "collector_timeout"`, empty
  `reason.groups` — which means there is no code path on which a timeout can
  become a permit. Pinned by `createApp — a stalled collector denies (#115)`,
  which asserts a deployment that *does* allow an empty rule set still denies a
  stalled one.

  It is a deny and not a `5xx` on purpose: a 5xx invites the enforcement layer
  to retry the same stalled dependency, or to conclude the PDP is down and apply
  a fallback nobody in this repo wrote. The wire message names no collector and
  no bound — that reaches the caller, and the collector set is deployment
  topology; the detail goes to the `collector_timeout` log line. The decision
  still emits its `decision` audit line and increments the deny counters, so a
  timeout is visible as what it is rather than disappearing into the 500 rate.
  In a batch the bound is per decision: one entry timing out denies that entry
  and leaves the rest decided.

  **Rule purity is unchanged in strength.** The signal lands on the very object
  `describeRulePurityConformance` revokes, and it is the first context field a
  collector is *meant* to hold live — but only for the length of `collect`.
  `aborted` moves on its own, so a rule that carried a signal into `verify`
  would not be a function of `attrs`, and the suite revokes it exactly as it
  revokes `ctx.resource`. What had to change is the mechanism, not the check: an
  `AbortSignal` cannot be wrapped in a `Proxy` — its members are brand-checked
  against the receiver, so a proxied signal throws on `addEventListener`,
  `AbortSignal.any` and `fetch`, and the harness would have begun failing honest
  collectors for an artefact of its own. The view is now a real signal minted by
  `AbortSignal.any` (linked to the case's own, so cancellation still propagates),
  and revoking shadows its members with accessors throwing the same `TypeError` a
  revoked proxy throws. Both halves are pinned: a rule holding the signal is
  rejected, and a collector using it in every legitimate way passes.

- **BREAKING**: `/verify` and `/verify/batch` now hold the request body to
  stated limits, refuse unknown properties and whitespace, and **validate the
  body before verifying the token**
  ([#118](https://github.com/o3co/auth.policy-verifier/issues/118)).

  Input validation was thin: Express's unstated 100 KB JSON default, and a
  check that `resource` and `action` were non-empty strings. A whitespace-only
  value passed, `context` could be arbitrarily wide and deep, unknown
  properties rode along in silence — and the expensive half of the request, JWT
  verification, ran first, so an unauthenticated caller could spend it on a body
  that was never usable.

  **The limits**, each a numeric knob on the `verify` config block, read through
  the same `resolveBound` at both boundaries (#157) and settable from the
  environment:

  | Key | Env | Default | Bounds |
  | --- | --- | --- | --- |
  | `verify.maxBodyBytes` | `VERIFY_MAX_BODY_BYTES` | `65536` (64 KiB) | the `limit` on `express.json()` |
  | `verify.maxResourceLength` | `VERIFY_MAX_RESOURCE_LENGTH` | `512` | characters in `resource` |
  | `verify.maxActionLength` | `VERIFY_MAX_ACTION_LENGTH` | `64` | characters in `action` |
  | `verify.maxContextEntries` | `VERIFY_MAX_CONTEXT_ENTRIES` | `64` | properties + array elements in the whole `context` tree |
  | `verify.maxContextValueLength` | `VERIFY_MAX_CONTEXT_VALUE_LENGTH` | `1024` | characters in any `context` string, keys included |

  `maxBodyBytes` is below Express's old default, so it is a tightening, and it
  is the outer envelope: it binds first on a large batch, because the per-field
  limits bound *one* entry rather than N of them. A deployment sending wide
  contexts across a full 50-entry batch raises it.

  `maxContextEntries` counts every property and every array element at every
  depth, so nesting is **bounded rather than forbidden** —
  `RequestContextAttributeCollector` reads dot paths such as `tenant.id`, and a
  flat-only rule would have broken a documented feature. Since each level of
  nesting costs at least one entry, it bounds the depth too, which is why there
  is no separate depth knob.

  **Whitespace is refused, not trimmed**, in `resource` and `action` alike —
  the doctrine the resource grammar already applies (#117), extended to `action`
  and to a deployment that registered its own `ResourceParser`. Both are
  concatenated into the `{action}:{resourceType}` scope an issuer has to have
  granted, and RFC 6749 §3.3 makes space the delimiter between scope values, so
  a value carrying whitespace names something no issuer could grant. Trimming
  would make `"read "` and `"read"` one action here while a collector reading
  the raw string still saw two.

  **Unknown properties are refused.**
  `{"resource": "project:1", "action": "read", "subject": "admin"}` is now
  `400 invalid_request` rather than a decision with `subject` quietly dropped.
  The subject comes from the verified token and never from the body; a caller
  who sent one was being told nothing while believing it had been honoured. The same applies to a misspelled `contxt`, and to anything beside
  `decisions` on a batch body.

  **The ordering change, which is the wire-visible one.** The body is validated
  first, so a malformed request is answered `400` whether or not a token was
  presented:

  | Request | Before | After |
  | --- | --- | --- |
  | malformed body, no token | `401 missing_token` | `400 invalid_request` |
  | malformed body, bad token | `401 invalid_token` | `400 invalid_request` |
  | well-formed body, no/bad token | `401` | `401` (unchanged) |
  | body over the size limit | Express HTML `413` | `413 payload_too_large` (deny envelope) |
  | malformed JSON | Express HTML `400` | `400 invalid_request` (deny envelope) |
  | unreadable content type / charset | Express HTML `415` | `415 unsupported_media_type` (deny envelope) |

  It is the order the costs argue for: the body checks are bounded by the limits
  above, while verifying a token is the half that can reach the network — an
  attacker-chosen `kid` sends the JWKS path to the provider, and an HS256
  rotation tries every configured secret. What it costs is that an anonymous
  caller now learns whether a body was well-formed, the resource grammar
  included. `http.callerAuth` (#108) is the gate for a deployment that must not
  disclose even that, and it is **unchanged**: it still runs ahead of this
  router and ahead of `express.json()`, so a rejected caller is still answered
  before a body is parsed at all.

  **A terminal error handler** now turns a body-parser failure into the deny
  envelope instead of Express's default HTML page, which could also carry a
  stack trace outside production:

  ```json
  {"decision": "deny", "code": "invalid_request", "message": "Request body is not valid JSON"}
  ```

  That example is the response body verbatim, and it is the same line the two
  READMEs carry — `verifyInputValidation.test.mts` asserts it appears in all
  three and parses to what the endpoint emits, so no copy can drift from the
  code or from the others.
  The handler is mounted on the router, so a consumer mounting
  `createVerifyRouter` on their own app gets it without wiring anything. This
  covers item 6 of
  [#126](https://github.com/o3co/auth.policy-verifier/issues/126) in full,
  including its "whitespace-only `resource`" sibling, item 7. Neither message
  echoes the body: a parse failure is reported as a parse failure, not by
  quoting the bytes that caused it, and the unknown-property message bounds the
  names it shows.

  **Operator migration.** No configuration key is required, and every default is
  generous for a real caller: `project:1` / `read` and a handful of context
  fields are far inside all five. Callers to check are the ones sending bodies
  over 64 KiB, whitespace in `resource` or `action`, extra properties beside
  `resource` / `action` / `context`, or `context` objects with more than 64
  entries or strings over 1 KiB — and any client that special-cased the `401`
  it used to get for a malformed unauthenticated request.

- **BREAKING**: `CollectorContext.requestContext` is now an opaque
  `UntrustedRequestContext` instead of a `Record<string, unknown>`, so
  caller-supplied request data cannot be read without saying that is what it is
  ([#123](https://github.com/o3co/auth.policy-verifier/issues/123)).

  The request body's `context` is forwarded verbatim to every collector, and it
  arrived shaped exactly like the claim set beside it. A collector promoting
  `requestContext.role` into `ATTR_ROLES` is one line, indistinguishable at a
  glance from the line promoting `payload.sub` — and it hands any token holder
  the authorization input for its own request. Nothing in the type system marked
  the difference between "the issuer signed this" and "the caller typed this".

  Now the type marks it. `requestContext` carries its record behind a private
  symbol, which makes property access a compile error and leaves exactly one way
  in — `readUntrustedRequestContext(...)`, named for what it hands back. The
  brand is not a validation step and does not decide what a deployment may
  trust; it makes the trust level of every read visible at the line that reads
  it, and in review.

  **What a collector author must change** — every collector or rule collector
  that touches `requestContext`, one line each:

  ```diff
  -const v = context.requestContext?.subscriber_did;
  +const v = readUntrustedRequestContext(context.requestContext)?.subscriber_did;
  ```

  `readUntrustedRequestContext` is exported from
  `@o3co/auth.policy-verifier.core` and returns `Record<string, unknown> |
  undefined`, so an existing `?.` chain and the narrowing after it are unchanged
  — only the access is. Collectors that never read `requestContext` need no
  change, and no configuration key moves. `RequestContextAttributeCollector` in
  `builtins` is already updated, so a deployment that promotes context fields
  through config sees nothing at all.

  **A transport that builds a `CollectorContext` by hand** — a custom
  interceptor, or a test fixture — marks the record on the way in with
  `markUntrustedRequestContext(raw)`, which is the only thing that mints the
  brand. This repo's verify route does it for the HTTP body; a raw object no
  longer type-checks as a `requestContext`, which is what stops one reaching
  collectors unmarked.

  The seal is a runtime one as well: the payload hangs off a symbol key, so a
  serializer walking a `CollectorContext` — an audit line, a debug dump —
  cannot copy the caller's data out of it by accident.

  **Not changed, deliberately:** nothing validates or allowlists context keys at
  the framework level. Which fields a deployment may trust is not something the
  framework can know, and `RequestContextAttributeCollector` already offers the
  declared-allowlist shape for operators who want one.

- **BREAKING**: an HS256 secret must now carry at least **32 bytes (256 bits)**
  of key material
  ([#114](https://github.com/o3co/auth.policy-verifier/issues/114)). The only
  check before this was non-emptiness, so `OAUTH_JWT_SECRET=s` booted a
  verifier, and the shipped examples used values like `secret` and
  `your-secret`. HS256 is this project's default algorithm and it is symmetric:
  the value that verifies a token is the value that signs one, so guessing it
  is not read access to tokens, it is the ability to **mint** them for any
  subject. RFC 7518 §3.2 requires a key at least as wide as the hash output,
  and auth.provider holds the same shared value to the same floor
  ([auth.provider#282](https://github.com/o3co/auth.provider/issues/282)) — a
  floor that either side applies alone is a floor neither side has.

  **How it is measured.** On the **decoded** material, at the smallest
  plausible reading — the one an attacker gets to use. `openssl rand -hex 16`
  produces a 32-*character* value carrying 16 *bytes*, and counting characters
  would wave through a key of half the intended strength:

  | Value | Reads as | Verdict |
  | --- | --- | --- |
  | 64 hex characters (`openssl rand -hex 32`) | 32 bytes | passes |
  | 32 hex characters (`openssl rand -hex 16`) | 16 bytes | refused |
  | 43 base64 characters + `=` (`openssl rand -base64 32`) | 32 bytes | passes |
  | 32 random alphanumerics | 24 bytes — a base64 body | refused |
  | 32-character passphrase containing punctuation | 32 bytes | passes |

  Rejecting 32 alphanumerics is deliberate, not an artefact: 62 possibilities
  per character is ~5.95 bits, not 8, so such a value really does carry only
  ~190 bits. A value that is not a valid encoding — including a passphrase that
  merely ends in `=` — is measured on its raw UTF-8 length rather than being
  trimmed into a "base64 body" and scored short. What the check cannot see is
  structure: a 40-character English sentence measures 40 bytes and carries far
  less, so generate the secret randomly. This is a floor on key length, not a
  review.

  **One rule over every secret.** The floor applies to `oauth.jwt.secret` and
  to every entry of `oauth.jwt.previousSecrets` (the HS256 rotation added in
  [#112](https://github.com/o3co/auth.policy-verifier/issues/112)) in a single
  check, because they are the same kind of value: a retired secret is a live
  verification key for its whole overlap window, so it can mint tokens exactly
  as the current one can. Splitting the check would have left one of them the
  laxer half.

  Both boundaries enforce it, as with the JWKS transport check: `AppConfigSchema`
  rejects a short secret at config-parse time — so the deployment fails at boot,
  where an operator sees it — and the HS256 `KeyResolverFactory` repeats the
  check for hand-built configs that never met the schema. `insecure-decode`
  mode is unaffected: it uses no key material at all. `createVerifyRouter`
  takes key material directly rather than a config, and does not apply the
  floor; a consumer wiring a `KeyObject` by hand owns that check.

  The failure names the key the operator wrote and never echoes the value —
  these messages reach stdout, container logs and pasted bug reports:

  ```
  oauth.jwt.secret must carry at least 32 bytes (256 bits) of key material,
  but carries 11 — generate one with `openssl rand -hex 32`. Hex and base64
  values are measured on their DECODED length, so a 32-character hex string
  counts as only 16 bytes.
  ```

  **Operator migration** — every HS256 deployment whose secret is under the
  floor stops booting, which is the point:

  1. **Generate a conforming secret** and give the *same* value to
     auth.provider, which signs with it:

     ```bash
     OAUTH_JWT_SECRET=$(openssl rand -hex 32)     # or: openssl rand -base64 32
     ```

     Do not shorten it to fit an existing secret store field, and do not reuse
     a password. `openssl rand -hex 16` is **not** enough — that is 16 bytes.
  2. **Rotate rather than cut over**, if tokens are in flight. Changing the
     secret invalidates every token signed with the old one, so use the
     `previousSecrets` overlap window documented in the README's *Rotating the
     HS256 secret*: stage the new secret on the verifier first, move the
     provider, then demote the old secret with an `expiresAt` of your
     access-token TTL plus a buffer. Note the retired secret must itself clear
     the floor — a rotation *away from* a weak secret needs the old value
     dropped outright, and the outage that implies is bounded by the token TTL.
  3. **Or move off HS256.** With a symmetric algorithm every relying party
     holds a token-forging key. `algorithm = "RS256" | "ES256" | "EdDSA"` with
     `jwksUri` lets this verifier hold only a public key; auth.provider
     publishes the JWKS.
  4. **Update fixtures and scripts** that mint tokens with a short shared
     secret — they now fail at boot rather than at verification.
- **BREAKING**: a bearer token must now carry `exp` **and** `iat`, and is
  refused if it does not
  ([#110](https://github.com/o3co/auth.policy-verifier/issues/110)). jose
  enforces `exp` and `nbf` only when they are present, and nothing bounded a
  token's age, so a token minted — or forged — without `exp` was accepted
  forever. A fail-closed authorization service must not depend on the issuer's
  discipline for expiry.

  Both enforcement paths changed, which is the substance of the fix. The
  verifying path passes jose `requiredClaims: ["exp"]`, `maxTokenAge` and
  `clockTolerance`; the decode-only path (`oauth.jwt.mode = "insecure-decode"`)
  restates all three by hand in `assertTimeClaims`, because it has no key
  material and therefore no jose claim verification to inherit. A change
  threaded only into `jwtVerify` would have left decode-only deployments
  accepting the very token this issue is about — the two paths are held to the
  identical outcome by the `token-expiry` conformance suite, which runs against
  both.

  Two new keys, both of which apply in **every** mode:

  - `oauth.jwt.maxTokenAgeSeconds` (default `86400`, env
    `OAUTH_JWT_MAX_TOKEN_AGE_SECONDS`) — ceiling on `now - iat`. This is what
    refuses an ancient-but-unexpired token: an `exp` the issuer set years out
    no longer outlives the ceiling. Setting it is what makes `iat` required.
    Positive whole seconds; there is deliberately no "off" value, since a
    switch that removes the ceiling is the failure this closes.
  - `oauth.jwt.clockToleranceSeconds` (default `0`, env
    `OAUTH_JWT_CLOCK_TOLERANCE_SECONDS`) — skew allowance applied to `exp`,
    `nbf` and the age ceiling alike. Bounded to `0`–`300`: tolerance lengthens
    the accepted life of every token the deployment sees, so an unbounded knob
    is a way to spell "expiry optional" without writing it down. `60` matches
    the skew auth.provider allows and is the value to reach for when the issuer
    and the verifier keep separate clocks.

  `exp` itself has no knob. RFC 9068 §2.2 requires both claims of an access
  token, so a conforming issuer needs no change.

  **Operator migration** — a deployment breaks only if something presents a
  token with no `exp` or no `iat`, or one older than a day:

  - **Check the issuer first.** auth.provider stamps `iat` unconditionally and
    `exp` whenever `oauth.accessToken.expiresIn` is set (default `3600`), so a
    verifier paired with it needs nothing. A hand-rolled minting path that
    omitted `expiresIn` must start setting it — that path was producing
    permanent credentials.
  - **Long-lived tokens**: raise `maxTokenAgeSeconds` to cover the longest
    lifetime the issuer actually mints (`OAUTH_JWT_MAX_TOKEN_AGE_SECONDS`). It
    is a ceiling, not a session policy — set it to a real number rather than
    something enormous, or the ceiling stops meaning anything.
  - **Separate clocks**: if tokens start failing right at the boundary, set
    `clockToleranceSeconds = 60` rather than widening `maxTokenAgeSeconds`.
  - **Test fixtures and scripts** that minted tokens without an expiry now get
    `401 invalid_token`. Add an expiry; do not reach for the tolerance knob.

  Rejections log `jwt_token_rejected` at warn as before, with
  `err.code` naming which check failed — `ERR_JWT_CLAIM_VALIDATION_FAILED`
  (with `claim` `exp` or `iat`, reason `missing`) for an absent claim, and
  `ERR_JWT_EXPIRED` for one that expired or was issued too long ago.
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

- `qs` and `body-parser` are pinned above two advisories that the new
  `pnpm audit --prod --audit-level=low` gate refuses:
  [GHSA-q8mj-m7cp-5q26](https://github.com/advisories/GHSA-q8mj-m7cp-5q26) (a
  remotely triggerable `qs.stringify` DoS) and
  [GHSA-v422-hmwv-36x6](https://github.com/advisories/GHSA-v422-hmwv-36x6)
  (`body-parser` silently disabling size enforcement when given an invalid
  limit). Both reach this workspace only through `express`, a production
  dependency of `@o3co/auth.policy-verifier.server`.

  This was a stale lockfile rather than an exposure for consumers:
  `express@5.2.1` asks for `qs@^6.14.0` and `body-parser@^2.2.1`, both of which
  admit the patched releases, so an install resolving today already floats to
  them — but `pnpm-lock.yaml` had pinned `qs@6.15.0` and `body-parser@2.2.2`.
  The `overrides` block added to `pnpm-workspace.yaml` scopes each entry to the
  vulnerable range, so it lapses on its own once `express` requires a fixed
  version instead of holding the floor down indefinitely.

- **BREAKING**: an empty rule set is now a **deny**, not an allow
  ([#104](https://github.com/o3co/auth.policy-verifier/issues/104)).

  `evaluate` returned `{ decision: "allow" }` whenever no rule was collected, so
  a scope-only pipeline allowed any validly-signed token that carried no `scope`
  claim — for every resource and every action. The paired provider mints exactly
  such tokens (id_tokens among them), so this was reachable with a credential a
  deployment hands out by design. `evaluate` now denies an empty rule set with
  `no_applicable_rule`; `EvaluateOptions.onEmptyRuleSet: "allow"` is the explicit
  opt-out, surfaced as `rule.onEmptyRuleSet` in the server config.

  Paired with it, `ResourceActionScopeRuleCollector` no longer stays silent on a
  scopeless token: it emits its `HasScope` rule regardless, `scopeless` defaulting
  to `"deny"`. Emitting nothing was the other half of the same hole — a permissive
  absence, which is the shape this release spent several changes eliminating.
  Pipelines that genuinely serve scopeless flows (DID grants) opt out with
  `{ scopeless: "skip" }`, which is only safe when another rule group decides,
  since an empty rule set is now a deny. `createApp` also fails at boot when no
  rule collector is configured at all — such a pipeline can never authorize
  anything.

  **This is the most consequential semantic change in 0.4.0.** A deployment that
  relied on the old fall-through (knowingly or not) starts denying at upgrade.
  Set `rule.onEmptyRuleSet = "allow"` to keep the previous behaviour, and treat
  needing it as a finding.

- **BREAKING**: `iss`, `aud` and the `typ` header are validated, per RFC 9068 §4
  ([#105](https://github.com/o3co/auth.policy-verifier/issues/105)).

  `jwtVerify` was called with `{ algorithms }` alone, so acceptance rested on the
  signature and `exp`. The paired provider signs access tokens, id_tokens
  (`id+jwt`), refresh tokens (`rt+jwt`, which carry `scope`) and logout tokens
  with one key, and neighbouring services share issuers — so a caller could
  present any of those, or a token minted for another audience, and have it flow
  into rule evaluation. `createVerifyRouter` now checks `iss` against `issuer`,
  `aud` against `audience`, and the `typ` header against `tokenType`.

  A 0.3.1 configuration that verified signatures only will **fail at boot** until
  it declares the issuer and audience it accepts.

- The rejection log no longer carries the token's claim set.

  `jwt_token_rejected` logged the jose error object. `JWTExpired` and
  `JWTClaimValidationFailed` are thrown *after* the signature verifies, and jose
  hangs the entire decoded token off each one as an own `payload` property — so
  every expired token wrote its whole claim set (`sub`, `email`, group
  membership, any custom claim the issuer mints) into the log. Expiry is routine
  traffic, not an incident, so this was a steady stream of other people's data
  into the log aggregator, and a token minted for a *different* audience leaked
  its claims here too.

  The line now carries a projection — `name`, `message`, and jose's `code` /
  `claim` — which is what tells `ERR_JWT_EXPIRED` from a signature failure or an
  `iss` mismatch, without quoting any value. This restores the rule
  `observability/decisionEvent.mts` already states for the decision line: a claim
  set is not needed to explain an outcome. Introduced during this release cycle,
  so no released version shipped it.

### Added

- **`POST /verify/batch` — many decisions in one request**
  ([#124](https://github.com/o3co/auth.policy-verifier/issues/124)). Body
  `{ decisions: [{ resource, action, context? }, …] }`, answered as
  `200 { decisions: DecisionResponse[] }` in request order. The `200` is about
  the batch being decided, not about any entry being allowed — each entry
  carries its own `decision`, and a batch of denies is still a `200`. Entry
  count is bounded by `verify.maxBatchSize`
  ([#157](https://github.com/o3co/auth.policy-verifier/issues/157)); an
  oversized batch is refused rather than trimmed.

  The same change thickened the single-decision contract that the batch entries
  reuse: `reason.groups[]` structured reasons — renamed and extended under
  *Changed*, below — and a request-context collector.

- **A wire-contract conformance suite, so "drop-in replaceable behind
  `VerifierEndpoint`" is a claim this repository can fail**
  ([#125](https://github.com/o3co/auth.policy-verifier/issues/125)). The
  interface an enforcement layer codes against lives in
  [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors), so
  nothing here checked that the wire shape this service publishes is the wire
  shape that repository implements. A field rename or a status remap would have
  been invisible until it broke every caller at once, at runtime.

  `describeWireContractConformance` joins the other suites in
  `tests/integration/src/conformance/`, and it is the odd one out on purpose:
  the rest are engine-agnostic and pin the seam *underneath* the endpoint, while
  this one pins the HTTP surface *above* it — statuses, the exact key set of
  every response body, and which refusal wins when a request is wrong in two
  ways at once. Its adapter is a transport rather than an engine, so an OPA or
  Cedar deployment of this same service satisfies it by answering identically
  over HTTP, which is precisely what the swap promise means.

  **The fixtures are JSON files** (`conformance/fixtures/wireContract/`), not
  literals in the runner. The enforcement layer is a different repository and
  need not be TypeScript; a table it can read is the only version of this
  contract that can be shared rather than re-typed, and re-typing it is the
  drift #125 was filed about. `requestCases.json` is every refusal — status,
  code, and what the message must and must not name — and
  `responseEnvelopes.json` is the key set of each response body, exhaustive in
  both directions: a response carrying a key the contract never promised fails
  as readily as one missing a key it did.

  It pins the contract **as #118 and #115 left it**, not as it was: a malformed
  body is `400 invalid_request` whether or not a credential was presented (it
  was `401` before #118), an oversized body is a `413 payload_too_large` deny
  envelope rather than Express's HTML page, whitespace in `resource` or `action`
  is refused rather than trimmed, an unknown property is refused and named,
  `subject` is omitted when the token carries no `sub` (#158), `satisfiedBy`
  appears on a passing rule group only (#135), and a collector fan-out that runs
  out of time is `403 collector_timeout` with an empty `reason.groups` (#115).
  `POST /verify/batch` is pinned alongside it — the envelope, the preserved
  order, `200` even when every entry denies, and the refusal that names the
  offending index and rejects the whole batch before any entry is decided.

  The deny envelope the READMEs print verbatim is now read from
  `responseEnvelopes.json` by `verifyInputValidation.test.mts` instead of being
  restated there, so the shape has one definition rather than a fourth copy.

- **A rule-purity conformance suite, so the contract `evaluate()` spends is one
  something can fail** ([#152](https://github.com/o3co/auth.policy-verifier/issues/152)).
  `evaluate()` runs every rule group rather than stopping at the first failure
  and justifies it in a comment — "Rules are pure predicates over attributes by
  contract, so running them all is safe." Nothing checked that: not a runtime
  check, not the type system, not lint, not CI, not a conformance suite. The
  four existing suites are all engine-level; none could be pointed at a rule.

  `describeRulePurityConformance` (and the `assertRuleIndependentOfContext`
  primitive under it) joins them in `tests/integration/src/conformance/`. It
  runs the contract's deciding test literally: the rules are collected through a
  **revocable** view of the `CollectorContext`, the view is revoked, and every
  rule is asked again. A rule that copied a string out at collect time answers
  identically; a rule that kept the request — or any object reached through it,
  which is why the view is revoked all the way down rather than at the top
  level — throws on the access, named in the failure. Determinism and
  non-mutation are checked in the same pass.

  Because the check is behavioural, it cannot be satisfied by renaming a
  variable, and its own negative cases are part of the suite: the violating
  shapes from `app.test.mts` and `metrics.test.mts` are run through it to prove
  it rejects them. Both builtin rule collectors are held to it and both pass.

  CI additionally greps `verify` bodies for `ctx.` / `context.` reads. That is a
  textual backstop for the obvious shape — it brace-matches the body rather than
  reading a line, but it is still a string search and does not see a context
  reached through a differently-named binding or a helper. It exists because the
  violation has now been written twice by copy-paste; the conformance suite is
  the check.

- **A per-decision audit log and a `GET /metrics` endpoint, so the PDP can
  answer "why was this denied?" from its own output**
  ([#111](https://github.com/o3co/auth.policy-verifier/issues/111)). There was
  no decision logging and no metrics anywhere: no record of allow/deny, no
  counter of decisions by outcome, no `/metrics`. `x-request-id` was read off
  the request and handed to collectors but never emitted, so a decision could
  not even be correlated with the caller's own trace. For an authorization
  decision point those are not optional telemetry — they are the operational
  surface, and without them an incident involving the PDP is undiagnosable.

  **The decision log.** Every decision now emits one structured event named
  `decision`, at `info`, through the same injected logger the failure events
  (#107) already used:

  ```json
  {"msg":"decision","requestId":"6f1c…","sub":"user-42","resource":"project:7","action":"read","decision":"deny","code":"invalid_scope","deniedBy":{"ruleType":"scope","refused":["invalid_scope"]},"durationMs":0.412}
  ```

  On an allow, `satisfiedBy` names the rule that satisfied each group —
  `RuleGroupOutcome.satisfiedBy` from
  [#135](https://github.com/o3co/auth.policy-verifier/issues/135), which is the
  rule that *decided* rather than merely the last one that ran. On a deny,
  `deniedBy` names the first failing group and every alternative in it that
  refused. One line per decision, so a `POST /verify/batch` of N entries emits N
  lines sharing one `requestId`, and `durationMs` measures the collector
  pipelines plus the evaluator rather than the HTTP round trip.

  `logging.level` (`LOG_LEVEL`) is the switch: the line is `info`, so `warn`
  turns the stream off and there is no second flag to forget. It is deliberately
  **not** at `warn` — a deny is a normal outcome for a decision point, and
  routing it there would let any caller manufacture warn-level noise until
  `warn` stopped meaning "something is wrong".

  **Never on the line:** the raw bearer token, the claim set beyond `sub`, and
  the caller's `context` object. The last of those is free-form and forwarded
  verbatim to collectors, so it is exactly where a calling service's own request
  payload ends up; logging it would make the audit stream a copy of that
  payload. This record is written on every request, successes included, and
  shipped to an aggregator whose blast radius is not the token's.

  **`GET /metrics`** serves the Prometheus text exposition format:
  `auth_decisions_total{decision}` (the allow/deny rate, exactly two series),
  `auth_denials_total{code}` (which rule is denying — the aggregate of the log
  line's `deniedBy`), `auth_decision_duration_seconds{decision}`,
  `http_request_duration_seconds{method,route,status}`, and the Node process
  defaults under `auth_policy_verifier_`. The HTTP histogram carries the same
  name and label set as auth.provider's, so one Prometheus job and one dashboard
  convention cover both halves of the stack.

  **Every label is bounded**, because an unbounded one mints a fresh time series
  per distinct value — which is how a metrics endpoint takes down the monitoring
  that was supposed to watch it, and none of these needs access to `/metrics` to
  reach. `resource`, `action` and `sub` are **not labels at all**: they come from
  the request body or the token and are unbounded by construction, so they live
  on the log line, where high cardinality is the point. `route` is the Express
  route pattern with unmatched requests collapsing to `route="unmatched"`;
  `method` is an allowlist of the nine methods this service serves, everything
  else `"other"` (Node's parser hands the server every method llhttp knows);
  and `code` — operator-bounded in practice, but a field on the `Rule` interface
  that a custom collector could derive per request — is capped at 32 distinct
  values, after which the rest collapse to `code="other"`.

  **`/metrics` is not gated by `http.callerAuth` (#108).** Prometheus scrape
  configs carry `authorization`, `basic_auth` and `oauth2` — not an arbitrary
  header — so gating it on `x-caller-token` would make it unscrapable by a stock
  scraper, and the workaround would be handing the credential that authorizes
  *decisions* to the monitoring system. The endpoint publishes counts and
  latencies over bounded labels and nothing about any individual decision. The
  boundary is the bind address, which is loopback by default (#108): put the
  scraper on the host — a sidecar in the same Kubernetes pod shares the network
  namespace and reaches `127.0.0.1:3000/metrics` with the default untouched —
  and where the bind must be `0.0.0.0` (containers), restrict the port at the
  network layer exactly as for `/verify`. `http.pathPrefix` moves the endpoint
  with everything else, so `pathPrefix = "/pdp"` means `/pdp/metrics` and the
  scrape config's `metrics_path` has to match.

  **Deliberately not published yet:** a per-dependency `up` gauge like
  auth.provider's. The equivalent here is the JWKS endpoint and there is no
  readiness-probe registry to sample; a gauge built from a second,
  hand-maintained list of dependencies is the drift auth.provider avoided by
  sampling its probes. Until then a JWKS outage stays visible as the
  `jwt_verification_unavailable` log event, emitted at `error` so it can be
  alerted on.

  **Operator note:** `/metrics` is a new **unauthenticated** endpoint that every
  deployment picks up on upgrade, and the decision log is new output on stdout.
  Neither needs configuration. A deployment that must not expose `/metrics`
  should keep the bind loopback (the default) or restrict the port; a deployment
  that does not want the decision stream sets `LOG_LEVEL=warn`.
- HS256 signing-secret rotation, so the algorithm this stack ships as its
  default can be rotated without a coordinated outage
  ([#112](https://github.com/o3co/auth.policy-verifier/issues/112)). The
  verifier held exactly one secret, so the instant auth.provider began signing
  with a new one, every token already in flight was denied until both services
  had restarted in lockstep — a fleet-wide 401 with a restart order as its only
  mitigation.

  Two new keys on `oauth.jwt`, in auth.provider's own rotation shape so one pair
  of values moves on both sides:

  - `oauth.jwt.kid` (env `OAUTH_JWT_KID`) — names the secret the issuer signs
    with today, matching the `kid` auth.provider stamps into every token.
  - `oauth.jwt.previousSecrets` — a list of `{ kid, secret, expiresAt }`, each a
    secret this deployment also accepts and the moment it stops accepting it.
    `expiresAt` is an ISO 8601 timestamp, evaluated per request, so an overlap
    window closes without a restart.

  Both are optional and both default to absent, which is exactly the previous
  behaviour: with no `kid` and no `previousSecrets`, one `secret` verifies every
  token and the header is never consulted. **Nothing changes for a single-secret
  deployment** — including one whose provider stamps a `kid` the verifier has
  never been told about.

  Two details worth knowing before configuring it:

  - **A token carrying no `kid` is still accepted.** `kid` is optional per
    RFC 7515 §4.1.4, and a symmetric token has no JWKS to look one up in, so
    tokens minted with a bare `{ alg: "HS256" }` header genuinely occur.
    Rotation must not turn those into a second outage, so a token without a
    `kid` is tried against every configured secret in turn. One with a `kid` is
    resolved by direct lookup, and an unconfigured `kid` is refused — the same
    model auth.provider uses, which never trial-verifies.
  - **`previousSecrets` is capped at 3 entries.** That trial is one signature
    check per configured secret, on the decision hot path, driven by an
    unauthenticated request — so the length of the list is the work an
    unbounded config would hand out. Three covers a rotation, plus a second one
    started before the first window closed, plus a spare. A longer list is not
    rotation but accumulation, and every entry in it can still *mint* tokens.

  **Operator procedure** — rotating the shared secret with no window:

  1. Generate the new secret: `openssl rand -hex 32`.
  2. **Verifier first.** Keeping the old secret as `secret`, add the *new* one
     to `previousSecrets` with an `expiresAt` past the cutover, set `kid` to the
     old secret's name, and restart. The verifier now accepts both; what the
     provider mints has not changed.
  3. **Then the provider.** Move it to the new `kid` / `secret`, keeping the old
     pair in *its* `previousSecrets`, and restart. Tokens now arrive signed with
     the new secret, and the verifier already accepts them.
  4. **Verifier again.** Swap the roles — new secret as `kid` / `secret`, old
     one in `previousSecrets` with an `expiresAt` of the access-token TTL plus a
     buffer (auth.provider ships one-hour tokens) — and restart.
  5. When that timestamp passes the retired secret stops verifying on its own.
     Delete the entry from both configs at your convenience.

  The field carries auth.provider's name, but on the verifier it means every
  secret accepted *besides* the current one, which is why step 2 stages the
  incoming secret there: an outage-free rotation needs the verifier to span the
  cutover from both sides.

  A malformed rotation block fails at config-parse time, at boot, naming the
  entry: a non-list `previousSecrets`, a missing or non-ISO `expiresAt`, a `kid`
  duplicated across entries, more entries than the cap, or `previousSecrets`
  with no `kid` naming the current secret. `previousSecrets` under RS256 /
  ES256 / EdDSA is refused rather than ignored — **an empty `previousSecrets = []`
  included**, since the check is on the key being present, not on it having
  entries — because those algorithms rotate through the JWKS at `jwksUri`,
  mirroring the guard auth.provider applies in the other direction. `kid` is
  the exception: it is accepted and ignored under the asymmetric algorithms,
  which match it against the JWKS they fetch, so it never breaks their boot.
  The HS256 `KeyResolverFactory` repeats every check when it builds the key
  set, so a hand-built config that never went through `AppConfigSchema` still
  fails inside `createApp` rather than serving.

  The only spellings of "nothing is being rotated" are **omitting
  `previousSecrets`** and `[]`. A `null` is refused, identically at the schema
  and at the runtime guard — every other optional key in the `oauth.jwt` block
  reads the same way, and a `null` reaching a config was produced rather than
  written (an unrendered template value, a missing env var), which makes "no
  rotation configured" the wrong thing to conclude from it. This is a
  deliberate, narrow divergence from auth.provider's `narrowPreviousSecretsArray`,
  which reads `null` as an explicit opt-out; the wire contract this ports — the
  `{ kid, secret, expiresAt }` triple and the kid-overlap semantics — is
  unchanged.

  A token whose `kid` matches nothing configured is rejected with
  `ERR_JWKS_NO_MATCHING_KEY`, logged at **warn** as `jwt_token_rejected`, not at
  error: `kid` is attacker-controlled, and an operator alerting on error must
  keep seeing provider outages rather than a stream of invented key ids
  ([#107](https://github.com/o3co/auth.policy-verifier/issues/107)).
- `@o3co/auth.policy-verifier.server` exports `checkHs256Rotation` /
  `parseHs256Rotation` (with `Hs256PreviousSecret`, `Hs256Rotation`,
  `Hs256RotationCheck`, `Hs256RotationConfig`, `Hs256RotationIssue`) and the
  constant `MAX_PREVIOUS_SECRETS`
  ([#112](https://github.com/o3co/auth.policy-verifier/issues/112)), for
  consumers building a JWT config by hand or registering their own HS256 key
  resolver. They apply the identical contract the schema does, so a hand-built
  config gets the same answer as a parsed one. Both now also apply the entropy
  floor over `secret` and every `previousSecrets[].secret`
  ([#114](https://github.com/o3co/auth.policy-verifier/issues/114)) — a config
  with no rotation at all is still checked, since the floor is one rule over
  every HS256 secret rather than a rotation-only concern.
- `@o3co/auth.policy-verifier.server` exports `measureSecretEntropyBytes` and
  `describeWeakSecret` with the constant `MIN_SECRET_ENTROPY_BYTES`
  ([#114](https://github.com/o3co/auth.policy-verifier/issues/114)), so a
  consumer that accepts its own operator secrets — a custom key resolver, a
  composition root assembling a JWT config — applies the identical reading
  rather than a second opinion about what a 32-character hex string is worth.
  `describeWeakSecret` takes the measurement and not the secret, which is the
  guarantee that a rejection cannot echo the value into a log.
- `@o3co/auth.policy-verifier.server` exports `resolveJwtTimeClaimBounds`
  (with `JwtTimeClaimConfig` / `JwtTimeClaimBounds`) and the constants
  `DEFAULT_MAX_TOKEN_AGE_SECONDS`, `DEFAULT_CLOCK_TOLERANCE_SECONDS` and
  `MAX_CLOCK_TOLERANCE_SECONDS`
  ([#110](https://github.com/o3co/auth.policy-verifier/issues/110)), for
  consumers mounting `createVerifyRouter` directly or building a JWT config by
  hand. It applies the same defaults, coercion and range checks the schema
  does, so a hand-built config gets the same answer as a parsed one.
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
  - **Optional in v0.4.0** and off unless configured, so existing
    deployments (and container-to-container callers such as the cross-repo E2E)
    keep working. An empty `HTTP_CALLER_AUTH_TOKEN=` is rejected at boot rather
    than read as "disabled". Making it mandatory later is a one-line change to
    `CALLER_AUTH_REQUIRED` in `@o3co/auth.policy-verifier.server`'s
    `config/defaults` — see that constant's doc comment.
  - A shared credential is a floor, not a ceiling: it does not replace network
    policy or mTLS between the enforcement layer and this service.

- `@o3co/create-auth-policy-verifier` now generates `pnpm-lock.yaml` for the
  project it scaffolds, and accepts `--no-lockfile` to skip it
  ([#119](https://github.com/o3co/auth.policy-verifier/issues/119)). The
  template's `Dockerfile` installs with `--frozen-lockfile`, which needs a
  lockfile the template itself cannot ship: until the scaffolder has replaced
  every `workspace:*` with a published version, the dependency set a lockfile
  would pin does not exist. It is therefore resolved once, at scaffold time,
  against the rewritten `package.json` (`pnpm install --lockfile-only
  --ignore-workspace`) — commit the result.

  Best-effort by design: it needs `pnpm` (or `corepack`) and a reachable
  registry, and neither is guaranteed on the machine running the scaffolder.
  Failure prints what to run and leaves the scaffold successful, because the
  generated project is usable without a lockfile — it just cannot be built into
  an image until `pnpm install` has been run once. `generateLockfile` is
  exported alongside `scaffold` for programmatic use, and reports failure as a
  result rather than throwing.

### Changed

- **BREAKING**: JWT key resolution moves to the Module/Registry pattern —
  `createKeyResolver` and the `JwtKeyConfig` type are gone from
  `@o3co/auth.policy-verifier.server`'s public surface
  ([#37](https://github.com/o3co/auth.policy-verifier/issues/37),
  [#38](https://github.com/o3co/auth.policy-verifier/issues/38)).

  Key resolution was the last strategy routed through a hard-coded if-chain over
  a closed `z.enum(["HS256","RS256","ES256","EdDSA"])`, so a user-defined
  algorithm could be implemented but never selected from config. It now uses the
  same Module + Registry shape as `AttributeCollector`, `RuleCollector` and
  `ResourceParser`.

  A 0.3.1 caller that imported `createKeyResolver` (or annotated with
  `JwtKeyConfig`) must drop the import and pass `builtinKeyResolversModule` in
  `createApp({ modules })` instead. `KeyResolver` itself survives — though as of
  [#170](https://github.com/o3co/auth.policy-verifier/issues/170), below, it is
  exported from the server package rather than from core.

- **BREAKING**: `AttrLiteralIn` / `AttrLiteralNotIn` `ruleType` strings change —
  `computeValuesKey` hashes with FNV-1a 64-bit instead of `node:crypto` SHA-256
  ([#34](https://github.com/o3co/auth.policy-verifier/issues/34)).

  This removed the only `node:*` import in core and builtins, so both packages
  now load on edge and non-Node server runtimes (Cloudflare Workers, Deno, Bun,
  Vercel Edge) alongside Node.js 22+. **Browsers are deliberately not on that
  list**: a browser-side decision can be bypassed by patching the JS, so
  authorization must be enforced server-side. (An earlier README revision listed
  them by mistake; the corrected wording ships in 0.4.0.)

  The hash is wire-visible — it appears in `reason.groups[].ruleType` — so
  anything asserting on those exact strings needs updating. 64-bit was chosen
  over 32-bit during review: short random strings collide under FNV-1a 32-bit
  within seconds, and a collision would silently OR-combine distinct rules on the
  same attribute, weakening authorization rather than merely mislabelling it.

- **BREAKING**: core's input vocabulary is neutral — `CollectorContext.payload:
  VerifierPayload` becomes `subject: SubjectAttributes`, and
  `KeyResolver` / `KeyResolverFactory` move to the server package
  ([#170](https://github.com/o3co/auth.policy-verifier/issues/170), the one
  purpose-distortion of the o3co/auth#11 audit). Core sold itself as the
  neutral engine ("drop-in replaceable with OPA or Cedar"), but its context
  required a JWT claim set by type: a subject could not reach the engine except
  as claims. The pin was type-only — the engine never read a claim field — so
  the fix is a rename, not a redesign:

  - **core**: `VerifierPayload` is replaced by `SubjectAttributes`
    (`{ readonly [key: string]: unknown }` — a verified-attributes bag with no
    named JWT fields), and the context field is `subject`. The `KeyResolver` /
    `KeyResolverFactory` types and the `keyResolverRegistry` slot of
    `ModuleContext` leave core; `Module<C extends ModuleContext =
    ModuleContext>` is now generic so a host can initialize modules with a
    wider context. `Registry` stays in core.
  - **server**: `KeyResolver` / `KeyResolverFactory` now live in
    `@o3co/auth.policy-verifier.server`, alongside the new
    `ServerModuleContext` (the base context plus `keyResolverRegistry`) that
    `createApp` initializes modules with; `builtinKeyResolversModule` is a
    `Module<ServerModuleContext>`. The JWT→bag mapping now visibly lives at
    one edge: the token authenticator spreads the verified claims (plus
    `authScheme`) into the bag, and `AuthenticationResult` carries `subject`
    instead of `payload`.
  - **builtins**: `PayloadSubjectIdCollector`, `PayloadScopeCollector` and
    `ResourceActionScopeRuleCollector` read `subject.sub` / `subject.azp` /
    `subject.scope` with local narrowing — claim vocabulary is builtins'
    vocabulary. A claim that is not a non-empty string is no longer promoted
    (previously a non-string `sub` would have been). **Registered collector
    names are unchanged.**

  **The runtime wire contract, HOCON keys, env vars and collector registration
  names are all unchanged** — only TypeScript types and field names moved.
  **Migration:** a custom collector reads `context.subject` where it read
  `context.payload` (narrowing values itself — the bag is `unknown`-valued); a
  consumer importing `VerifierPayload` uses `SubjectAttributes`; one importing
  `KeyResolver` / `KeyResolverFactory` imports them from the server package; a
  module registering key resolvers types itself `Module<ServerModuleContext>`.
  Note the removed/renamed fields compile silently for consumers that only
  index into the bag — the open index signature admits any key — so treat this
  entry, not the compiler, as the migration signal.

- **BREAKING**: collectors no longer receive the raw credential unless the
  deployment states it —
  `VerifierPayload.token` is removed
  ([#175](https://github.com/o3co/auth.policy-verifier/issues/175), from #126
  item 1). Every collector received the raw, replayable bearer token via
  `CollectorContext.payload`; a collector that logged its context leaked a live
  credential. Collectors now get verified claims only. The one legitimate use —
  a project-side collector calling a downstream API *as the subject* (token
  forwarding/exchange) — opts in with `verify.credentialToCollectors =
  "expose"` (`VERIFY_CREDENTIAL_TO_COLLECTORS`; an enum, not a boolean, so the
  string an env substitution delivers needs no coercion path), which surfaces
  the credential as **`CollectorContext.credential`** — a stated, greppable
  config decision. **Migration:** a collector reading `payload.token` sets the
  config key and reads `context.credential` instead. The authenticator's
  `AuthenticationResult` now carries `credential` beside `payload`; the route,
  not the authenticator, owns the exposure decision.

- **BREAKING**: two collectors writing **different** values to the same scalar
  attribute key now deny the decision instead of silently last-writer-winning
  ([#174](https://github.com/o3co/auth.policy-verifier/issues/174), from #126
  item 2). A collector-ordering mistake used to weaken authorization with no
  signal anywhere; an attribute map whose content depends on collector order is
  not something to authorize from. The merge throws the new
  `AttributeConflictError` (exported from core; message names the KEY only —
  values are claims and may be sensitive), and `/verify` answers it exactly as
  it answers a #115 timeout: `403` with `decision: "deny"`, `code:
  "attribute_conflict"`, an empty `reason`, and the detail on the operator's
  log line. Identical re-writes (same primitive value, or the same object
  reference) are not conflicts, so trivially-redundant collectors keep working;
  array-valued keys are unaffected and still concatenate. **Migration** for a
  deployment that relied on deliberate override chains: give the key one owning
  collector, or namespace the keys.

- A scaffolded project keeps `"private": true`
  ([#126](https://github.com/o3co/auth.policy-verifier/issues/126) item 4).
  `create-auth-policy-verifier` used to delete the field, so the project it
  generated — an authorization service carrying policy code and config — was
  publishable by default, and an accidental `npm publish` succeeded. Publishing
  a scaffolded service is the rare intent; state it by removing the field.

- **BREAKING**: `HasPermission` matches exactly and case-sensitively
  ([#155](https://github.com/o3co/auth.policy-verifier/issues/155)).

  #116 made `HasScope` compare scope values exactly (RFC 6749 §3.3 makes them
  opaque), and #117 carried the same principle into
  `DotNotationResourceParser`: compare what was written, never a normalized
  guess at what was meant. The permission vocabulary was never visited —
  `HasPermission` lowercased both sides — so the exact divergence #117 closed
  had re-entered through the permission door: the parser preserves case, making
  `Project:1` and `project:1` two namespaces to a scope rule, while
  `ResourceActionPermissionRuleCollector` builds `{raw}.perm:{action}` from
  those same resources and `HasPermission` collapsed them into one.

  Wildcards in a **granted** permission are kept, deliberately: a `*` is match
  structure the policy author wrote into the grant, not a rewrite of both sides
  behind their back. The literal halves around it now also compare exactly and
  case-sensitively, and multiple wildcards still never match.

  **Migration:** a deployment relying on case-mixed permission grants (a role
  granting `Posts.*` against permissions built from a `posts:…` resource) now
  sees denials where it saw grants. The change only ever narrows — nothing
  that was denied before is granted now. Align the case of granted permissions
  with what the resource parser actually emits; `ATTR_PERMISSIONS` /
  `Role.permissions` values are compared verbatim.

- **BREAKING**: `VerifierPayload.tokenType` is renamed to `authScheme`
  ([#158](https://github.com/o3co/auth.policy-verifier/issues/158)).

  One name meant two unrelated things, and both of them appear in
  `jwt/tokenAuthenticator.mts`. In config, `tokenType` is the `typ` header the
  deployment accepts — `"at+jwt"`, RFC 9068 §2.1's access-token type, pinned so
  an `id_token` signed with the same key cannot pass. On the payload it was the
  `Authorization` scheme the token arrived under — `"Bearer"`, RFC 6750. Both
  readings have a standard behind them, which is how the collision survived; a
  reader who knows only the config key and then meets `payload.tokenType` in a
  collector has no way to notice they are looking at something else.

  The payload field is the one that gave the name up, for three reasons: it is
  not a token type at all but a fact about a request header; the config key is
  what every deployment's HOCON, the `OAUTH_JWT_TOKEN_TYPE` variable and both
  READMEs already say, so renaming *that* would break every config file to fix a
  name that is accurate; and the payload field is written on exactly one line
  and read by nothing in this repo.

  ```diff
  -const scheme = payload.tokenType;
  +const scheme = payload.authScheme;
  ```

  **This one does not fail to compile, and what is left behind is not empty.**
  `VerifierPayload` carries an open index signature so custom claims can ride
  along, so `payload.tokenType` is still a legal read — `unknown`, and the type
  checker will not point at a single call site. Grep for it rather than trusting
  `tsc`.

  What that read now returns has changed in kind, not just in value. The
  verifier built the payload as `{ ...decoded, token, tokenType: scheme }` —
  the claims spread **first**, then its own value written over the top — so a
  token carrying a `tokenType` claim had that claim silently overwritten with
  `"Bearer"` and could not be observed at all. The verifier no longer writes
  that slot. `payload.tokenType` is therefore whatever the token's claims
  contained, and `undefined` when the token carries no such claim.

  So this is a **new exposure**, not a claim that was always visible under
  another name: a field that used to hold the verifier's own near-constant
  string now holds token-supplied data, in the same shape as the trust boundary
  #123 drew around `requestContext`. The trust level is not identical and should
  not be overstated — in `mode = "verify"` these claims arrived under a verified
  signature from a pinned issuer, so this is issuer-attested data, not the
  caller-typed body that `UntrustedRequestContext` brands. In
  `mode = "insecure-decode"` no signature was checked at all. Either way it is
  no longer *the verifier's* value, and nothing validates a custom claim of that
  name.

  **What to do:** a collector that read `payload.tokenType` for the
  authorization scheme must move to `payload.authScheme`; it must not be left in
  place on the assumption that the field is now absent, because a token can put
  something there. If a deployment's issuer mints a `tokenType` claim, that claim
  becomes visible to collectors for the first time — which is a change worth
  knowing about even for a consumer that never read the field.

- **BREAKING (types only)**: `Rule.verify` now takes a `ReadonlyAttributes`
  (`ReadonlyMap<string, unknown>`) instead of `Attributes`
  ([#152](https://github.com/o3co/auth.policy-verifier/issues/152)).

  The evaluator hands the **same live map** to every rule in every group, so a
  rule that wrote into it would silently change the inputs of every group
  evaluated after it — and nothing said it must not. `Object.freeze` was
  considered and rejected: it does not affect a `Map`'s contents, whose entries
  live in an internal slot, so `map.set(...)` still succeeds on a frozen one. It
  would have been a guard that guards nothing. The type is the guard instead.

  **What a rule author must change:** a rule that annotates its parameter,
  one line each.

  ```diff
  -verify(attrs: Attributes): boolean {
  +verify(attrs: ReadonlyAttributes): boolean {
  ```

  `ReadonlyAttributes` is exported from `@o3co/auth.policy-verifier.core`. Every
  read a rule already does — `get`, `has`, `size`, iteration — is unchanged; only
  `set` / `delete` / `clear` are gone, and a rule that called one of those was
  violating the contract already. A rule written as an object literal typed
  `Rule` needs no change at all: it picks the parameter type up contextually.
  Note that TypeScript's method-parameter bivariance means an implementation
  that keeps the old `Attributes` annotation still *compiles* — it simply keeps
  write access it is not supposed to use, which is why the builtins were all
  moved over rather than left to the compiler.

  `Attributes` itself is **unchanged** and still a mutable `Map`:
  `AttributeCollector.collect` builds one by writing into it, and
  `AttributePipeline` merges them the same way. Only the rule's view is narrowed.

- **BREAKING (meaning, not signature)**: the Collector / Rule / Attribute
  contract in `AGENTS.md` has been rewritten, and it now forbids a different set
  of things ([#152](https://github.com/o3co/auth.policy-verifier/issues/152)).
  Anyone who wrote a custom rule against the old text should re-read it.

  The old sentence — "Rules must not reference `CollectorContext`, close over
  request state, or perform side effects" — was wrong in two opposite
  directions. It **illegalized** the project's own flagship pattern:
  `ResourceActionScopeRuleCollector` computes
  `` `${context.action}:${context.resource.resourceType}` `` at collect time and
  hands the string to `new HasScope(...)`, which "closes over request state" by
  the letter of the rule while leaving `HasScope.verify` a perfectly
  deterministic function of `attrs`. And the violation pattern it described —
  a rule returning a captured comparison "while ignoring `attrs`" — was too
  narrow to catch the real violation in this repo, which read `attrs` *and* the
  request.

  The prohibition has moved from **capturing at collect time** to **reading the
  context at verify time**:

  - `verify` must be a deterministic, side-effect-free function of `attrs`.
  - A rule **may** hold values fixed at collect time — *what it looks for*.
  - A rule **must not** retain `CollectorContext`, or any live reference into
    it, and read it inside `verify`.
  - The deciding test: collect the rule, discard the context, call
    `verify(attrs)` — the answer must be unchanged.

  So a rule that was legal under the old *text* may be illegal now (one that
  keeps `ctx` and reads it in `verify` — previously indistinguishable from the
  blessed pattern), and one that looked illegal is explicitly legal (fixing a
  comparand at collect time). No runtime behaviour changed for a rule that was
  already pure.

  Also **dropped**: the old text's prescribed fix, "a collector writes both
  values into attributes under well-known keys". For the scope rule that would
  have meant adding `ATTR_ACTION` / `ATTR_RESOURCE_TYPE` to core, which the
  Core Vocabulary Scope section directly below it forbids — those keys are
  request-shaped, not the transport-neutral OAuth/OIDC/RBAC subject facts
  `ATTR_*` is reserved for. Promoting both operands into attributes remains a
  fine thing for a *consuming project* to do under its own keys (see
  `metrics.test.mts`); it is no longer prescribed as the only correct shape.

- **BREAKING**: every numeric config knob is now read by one function at both
  boundaries, and a value that is not a whole number in range refuses to boot
  instead of being coerced into one
  ([#157](https://github.com/o3co/auth.policy-verifier/issues/157)).

  `AppConfigSchema` validates config files; the runtime guards validate the
  hand-built config objects `createApp` also accepts. Since #109 and #112 the
  URI and rotation invariants have shared **one** check function across both —
  `checkJwksUri`, `checkHs256Rotation` — precisely so that a hand-built config
  cannot get a different answer from a parsed one, which is the tiebreaker the
  `previousSecrets` `null` contract was decided on. The numeric knobs were the
  exception: the schema re-implemented each as a `z.coerce.number().int()…`
  chain and shared only the *constants* with `resolveBound`. They had already
  drifted, and silently:

  | config value | before, via a config file | before, hand-built | now, both |
  | --- | --- | --- | --- |
  | `oauth.jwt.jwksCooldownMs = false` | `0` — refetch on every miss | refused at boot | refused at boot |
  | `oauth.jwt.jwksTimeoutMs = true` | a 1 ms fetch timeout | refused at boot | refused at boot |
  | `oauth.jwt.clockToleranceSeconds = false` | `0` | refused at boot | refused at boot |
  | `oauth.jwt.maxTokenAgeSeconds = true` | a 1-second ceiling | refused at boot | refused at boot |
  | `verify.maxBatchSize = null` | refused at boot | the 50-entry default | refused at boot |
  | `http.port = "abc"` | `NaN` → an arbitrary bound port | — | refused at boot |
  | `http.port = false` | `0` → an arbitrary bound port | — | refused at boot |

  Both boundaries now call `resolveBound` with the same spec, so each knob has
  one default, one accepted range, and one refusal message naming the key the
  operator wrote. The specs live in one table (`config/bounds.mts`) rather than
  beside their consumers, because `jwt/tokenAuthenticator.mts` pulls in jose and
  `routes/verify.mts` pulls in express — a spec that lived next to either could
  not be shared with the schema without dragging those in behind it.

  **A boolean is refused rather than coerced**, at both boundaries. `Number(true)`
  is 1 and `Number(false)` is 0, so coercing invents a bound the operator never
  wrote — a one-millisecond JWKS timeout, or the zero cooldown that is exactly
  the fetch storm the knob exists to prevent. A boolean in a numeric slot is a
  configuration mistake, and HOCON hands the value over as a string in any case.
  A **blank string** is refused for the same reason: `VAR=` substitutes an empty
  string and `Number("")` is 0, which the knobs whose floor is 0 would otherwise
  read as a deliberate zero — the silent failure `http.callerAuth.token` already
  refuses.

  **The seven knobs, and what each now accepts** (unchanged unless noted):

  - `http.port` — 1 to 65535. **New bound**: this knob predated the doctrine and
    carried no `.int().positive()` at all, so `-1`, `70000`, `3.5` and `NaN` all
    reached `listen()`. `0` is excluded although `listen(0)` accepts it: it binds
    an arbitrary free port, so the address the enforcement layer was configured
    to call stops resolving to this process. (This is the straggler noted in
    [#158](https://github.com/o3co/auth.policy-verifier/issues/158), which can
    now drop it.)
  - `oauth.jwt.jwksTimeoutMs` — a positive integer number of milliseconds.
  - `oauth.jwt.jwksCooldownMs` — a non-negative integer number of milliseconds.
  - `oauth.jwt.jwksCacheMaxAgeMs` — a positive integer number of milliseconds.
  - `oauth.jwt.maxTokenAgeSeconds` — a positive integer number of seconds.
  - `oauth.jwt.clockToleranceSeconds` — an integer between 0 and 300 seconds.
  - `verify.maxBatchSize` — a positive integer number of entries.

  **`createVerifyRouter` now validates its `maxBatchSize` at construction.** It
  was the one knob with no runtime guard at all: `config.maxBatchSize ?? 50`
  read `null` as "unset" where the schema refused to boot, and let a `0` through
  as a cap that rejects every batch there is. Its type widens from `number` to
  `number | string`, matching `JwksFetchConfig` and `JwtTimeClaimConfig` — this
  is also a boundary a caller assembling a config from `process.env` reaches.

  **Not changed**: every value a working deployment already sets parses to the
  same number it did before, the defaults are the same, and the string form a
  HOCON `${?VAR}` substitution delivers is still accepted for every knob — the
  shared reader coerces it, which is what the schema's `z.coerce` used to do.
  `@o3co/auth.policy-verifier.server` additionally exports `DEFAULT_HTTP_PORT`
  and `MAX_TCP_PORT`.

  **Migration**: if a deployment sets any of these from a config file with a
  boolean, a `null`, an empty variable, or a fractional/out-of-range number, it
  now fails at boot with a message naming the key. Write the number it meant.
- **BREAKING (types only)**: the `EventLogger` port
  (`@o3co/auth.policy-verifier.core`) now requires `info` alongside `warn` and
  `error` ([#111](https://github.com/o3co/auth.policy-verifier/issues/111)).
  `EventLogger` is the narrow shape this project is willing to *demand* of a
  caller, and until now every event it carried was a failure. The per-decision
  audit line is emitted on the **successful** path, so a port with no
  non-failure level would have forced it to `warn` — which stops `warn` meaning
  "something is wrong" the moment a caller sends a request that is correctly
  denied.

  Nothing that satisfied the port before is excluded by this: every logger with
  `warn` and `error` has `info`, `Logger` still satisfies it, and a pino
  instance still needs no adapter. Only a hand-built object literal with
  *exactly* those two methods — a test double, typically — stops compiling. Add
  a no-op `info` to it. There is no runtime behaviour change for such a logger
  beyond receiving the new event.
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

- CI now gates dependency advisories and publish readiness, closing the gap
  against `auth.provider`'s pipeline for the same stack
  ([#122](https://github.com/o3co/auth.policy-verifier/issues/122)).

  `pnpm audit --prod --audit-level=low` runs before lint and build. It is
  exposed as the root `audit` script, which is what `make audit` has always
  called — that target was broken, because no such script existed
  ([#145](https://github.com/o3co/auth.policy-verifier/issues/145)); CI and a
  contributor's laptop now run the identical command.

  A `publish-readiness` job tarballs every package `pnpm -r publish` would
  offer to the registry — read back from pnpm rather than matched against a
  name pattern, so it cannot drift from the real publish surface — and then
  builds the scaffold out of the packed `@o3co/create-auth-policy-verifier`
  tarball against those tarballs, rather than against the `workspace:*` links
  a local build resolves. A template referencing a symbol that is not in the
  published tarball is invisible in the workspace, where `src/` is right there,
  and used to surface only after the tag was pushed. The job also asserts that
  no tarball ships compiled tests or a `#/` subpath specifier in `dist/`, and
  that `templates/versions.json` pins every workspace dependency the shipped
  template declares.

- Published tarballs no longer contain compiled test files. Each package's
  `tsconfig.json` excludes `src/**/__tests__/**`, so `dist/__tests__/` is no
  longer emitted or shipped by `.core`, `.builtins`, `.server` or
  `@o3co/create-auth-policy-verifier`. Those files also carried the only `#/`
  subpath specifiers that survived into `dist/`, which resolve through each
  package's own `imports` map to `./src/*` under the `development` condition —
  a path no tarball ships, so any consumer running under Vitest or `tsx watch`
  could resolve them into nothing. The scaffold's own
  `templates/standalone/src/__tests__/` is consumer-facing source and is still
  shipped, unchanged.

- `pnpm -r --if-present run typecheck` in `ci.yml` and `release.yml` was a
  no-op — no package defined a `typecheck` script, and `--if-present` swallowed
  it silently ([#145](https://github.com/o3co/auth.policy-verifier/issues/145)).
  Every workspace package now defines one, and both workflows call the root
  `typecheck` script (also `make typecheck`). It runs against a
  `tsconfig.typecheck.json` covering `src/**/*` *including* `__tests__`, which
  the build now excludes — so making the step real is what keeps test files
  type-checked at all. Turning it on surfaced three pre-existing type errors in
  `tests/integration`, a package that has no build step and had therefore never
  been type-checked; they are fixed.
- The standalone template's `Dockerfile` no longer rebuilds into a different
  image each time, and now ships a health signal
  ([#119](https://github.com/o3co/auth.policy-verifier/issues/119)).

  - **Reproducible inputs**: the base image is pinned by digest
    (`node:24-alpine@sha256:…`) rather than by a moving tag, global `corepack`
    is pinned to a version instead of resolving to whatever is latest at build
    time, and dependencies install with `pnpm install --frozen-lockfile` from a
    committed `pnpm-lock.yaml` instead of re-resolving every range. The
    lockfile is a required build input — a build without one fails at the
    `COPY` rather than quietly resolving something new. Dependabot's `docker`
    ecosystem now watches `templates/standalone`, so the digest is bumped
    deliberately rather than left to rot.
  - **Dependencies resolved once**: the runtime stage takes `node_modules` from
    a `pnpm prune --prod` of the same tree the build used, instead of running a
    second `pnpm install --prod`. A second install is a second resolution, and
    therefore a second chance for the runtime image to contain something the
    build never saw.
  - **Non-root**: `pnpm install` and `pnpm run build` run as `node` in every
    stage, matching the pattern auth.provider's template already uses.
  - The builder stage copies `tsconfig*.json` rather than `tsconfig.json`
    alone, so the `tsconfig.typecheck.json` the template now ships reaches the
    image and `pnpm run typecheck` works in the test and develop stages.
  - **`EXPOSE`** declares the port, derived from the same `HTTP_PORT` the app
    reads.
  - **`HEALTHCHECK`** probes `GET /healthcheck` — at the container's own
    routable address, not `127.0.0.1`. Since [#108] made the config bind
    loopback by default, a container that keeps that default is reachable from
    nothing, yet a loopback probe passes anyway: it would report `healthy` for
    a container no caller can reach. Probing the address the container is
    reachable at asks the same question a caller does, so a missing
    `HTTP_HOSTNAME=0.0.0.0` surfaces as `unhealthy` instead of being masked.
    The probe follows `HTTP_PORT` and `HTTP_PATH_PREFIX`, and needs no
    credential — `GET /healthcheck` is never gated by `http.callerAuth`.

    The one shape this is wrong for is a sidecar sharing a network namespace
    with its caller, where loopback is the correct bind; that deployment
    overrides `healthcheck:` on the service, which keeps the restart-driving
    signal honest for everyone else.

### Fixed

- A hand-built config with `oauth.jwt.tokenType` set to an **array** booted, and
  then rejected every token it was shown
  ([#164](https://github.com/o3co/auth.policy-verifier/issues/164)).

  `AppConfigSchema` types the key `z.string()`, so a config file carrying
  `tokenType = ["at+jwt"]` never started. `assertVerifyRouterJwtConfig` checked
  all three RFC 9068 fields with one presence test that accepts a non-empty list
  — correct for `issuer` and `audience`, which jose accepts as lists, and wrong
  for `tokenType`, which is the accepted `typ` header and a single value. The
  guard therefore let through a shape the schema refuses.

  The consequence was not a weakened check but a silent outage: jose lowercases
  the `typ` option to compare it against the token's header, which threw a bare
  `TypeError` off the array on **every** request. A `TypeError` is not a
  `JOSEError`, so the verifier judged it infrastructure-side and logged
  `jwt_verification_unavailable` at error level — the line #107 introduced to
  distinguish a JWKS outage from a bad token now pointing away from the config
  typo that caused it. The deployment answered `invalid_token` to every caller
  while reporting a provider problem.

  `tokenType` is now checked as a non-empty string at the guard, matching the
  schema. **Visible only to a JavaScript caller** building a config by hand:
  a `tokenType` array is refused at construction with
  `oauth.jwt.tokenType is required when …`, instead of booting into the failure
  above. TypeScript callers were already held to `tokenType: string` by
  `VerifyingJwtConfig`, and config files were already refused at parse.

  Found by the two-boundary parity table this issue added
  (`packages/server/src/__tests__/jwtConfigTwoBoundaryParity.test.mts`), which
  is the test AGENTS.md's "Two-Boundary Config Validation" section requires of a
  departure from its shared-check-function mechanism — and which had never been
  written for the one departure the section documents. Two implementations held
  in step by hand had drifted, as #157's numeric knobs had before them.

- The "How It Works" diagram in `README.md` and `README.ja.md` still put JWT
  verification first, contradicting the same file's own "Request Limits" section
  and the behaviour #118 shipped
  ([#125](https://github.com/o3co/auth.policy-verifier/issues/125)). The diagram
  is the first thing a client author reads, and it described the pre-#118
  ordering: a reader who took it at face value would have expected `401` for a
  malformed unauthenticated request, which is exactly the answer that changed.
  Body validation is now step 1, the remaining steps are renumbered, and the
  order is stated under the diagram rather than left to be inferred from it.
  Found while writing the #125 conformance suite.

- A decision response carried `subject: ""` for a token whose `sub` claim is
  present but empty, while the field's own documentation said it is absent when
  the token carries none — and while the audit line for the same decision had
  already dropped it
  ([#158](https://github.com/o3co/auth.policy-verifier/issues/158)).

  One value, two dispositions: a consumer joining a response to its `decision`
  log line found the subject in one and not the other. The response now omits
  the key, which is what `DecisionResponse.subject` (optional since it was
  written) already promised, and what an empty subject deserves — `subject: ""`
  names a subject that does not exist, and names the *same* non-existent one for
  every token without a `sub`. The route derives the subject once now and hands
  it to both the log line and the response, so the two cannot drift apart again.

  **Operator- and consumer-visible**: a client that read `subject` as a `string`
  for such a token now sees `undefined`. Client-credentials tokens with no `sub`
  at all were already answered this way, so a consumer handling that case
  correctly needs no change.

- The standalone template shipped a config that **denied every request**, and
  the smoke test did not notice because it exercised a different one
  ([#113](https://github.com/o3co/auth.policy-verifier/issues/113)).

  `templates/standalone/config/application.conf` enabled
  `ResourceActionPermissionRuleCollector` alongside the scope rule. That
  collector emits a `HasPermission` rule, rules are grouped by kind and every
  group must pass — and no collector in the shipped `attribute.collectors`
  produced permissions or roles. The permission group could not be satisfied by
  any token, so the scaffolded product answered deny to everything an operator
  ever asked it. The suite stayed green because `smoke.test.mts` assembled its
  own config with that collector left out: the one difference between the tested
  composition and the shipped one was the defect.

  **The shipped policy is now the token's `scope` claim and nothing else.** A
  request is allowed exactly when the bearer token carries
  `<action>:<resourceType>`, which `ResourceActionScopeRuleCollector` derives
  from the request. It is functional against any issuer that mints scopes with
  no authorization store to stand up first, and it is still fail-closed: a token
  carrying no scope or the wrong one is denied, and `rule.onEmptyRuleSet` stays
  `"deny"`. Nothing was granted by wildcard to make this work — the permission
  rule was removed, not satisfied.

  **For operators**, the change is visible: a deployment on the shipped
  `application.conf` went from denying everything to deciding on scopes. One that
  had already edited the file — the only way it could have worked — is
  unaffected, since a mounted or overlaid config replaces this one. A deployment
  that does want permission rules enables the rule collector **and** its
  supplier together; `application.conf` now carries that worked example beside
  the collector, and both READMEs state why one without the other is a verifier
  that denies everything.

  **The smoke test now boots from `config/application.conf`** through
  `loadAppConfig` — the same function `main.mts` calls — so the composition
  under test is the composition that ships, and the hand-built variant is gone.
  The HS256 secret, issuer and audience still come from the environment, as they
  must: the file deliberately carries no credential. One config in the file is
  still deliberately not the shipped one, the `allowBareScopeRewrite` opt-in, and
  it is derived from the shipped config so the key under test is the only thing
  that differs.

- `@o3co/create-auth-policy-verifier` scaffolded an **empty directory** whenever
  it was run the documented way. Its template-copy filter excluded any path
  containing a `node_modules` or `dist` segment, matched against the absolute
  path — and the scaffolder itself lives under `node_modules` when installed by
  `npm create` / `npx`, so the filter rejected every file of the template. It
  only ever worked from a source checkout. The exclusion is now judged relative
  to the template root, so build output inside the template is still skipped
  while the template itself is copied. The same latent bug in
  `create-app/scripts/copy-templates.mjs` was corrected too. Found while
  verifying [#119](https://github.com/o3co/auth.policy-verifier/issues/119)'s
  Docker build end to end.
- The scaffolder's printed next steps said `npm install` for a project whose
  `packageManager` is pnpm and whose lockfile is `pnpm-lock.yaml`; installing
  with npm would have ignored that lockfile and written a `package-lock.json`
  the image does not use. They now say `pnpm`.

[#108]: https://github.com/o3co/auth.policy-verifier/issues/108
