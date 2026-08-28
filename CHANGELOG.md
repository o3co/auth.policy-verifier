# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version sections follow the release labeling policy in
[`docs/release-policy.md`](docs/release-policy.md).

## [Unreleased]

### Security

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

### Added

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
  - **Optional in this release** and off unless configured, so existing
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
