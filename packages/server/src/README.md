# Server source map

Last updated: 2026-09-24

How `@o3co/auth.policy-verifier.server` is divided. The package's public API is
described in the [package README](../README.md); this page is where each piece
of it lives and where the boundaries between the pieces are.

## Responsibility

`src/` is the whole server: the assembly that turns config and modules into an
Express app ([`app.mts`](app.mts)), the public surface ([`index.mts`](index.mts)),
and one directory per concern below them. Consumers import only through
`index.mts`; everything else is internal, and the only runtime dependencies the
package has beyond core are pinned to a few files here — `jose` to
[`jwt/`](jwt/), `zod` to `config/application.schema.mts`, `prom-client` to
`observability/metrics.mts`, `express` to `app.mts`, [`routes/`](routes/),
`observability/metrics.mts` and (type-only) `http/callerAuth.mts`.

What this package does not own — evaluation semantics, the collector and rule
contracts, concrete collectors, the process lifecycle — is stated in the
[package README](../README.md#responsibility).

## Map

| Path | Role | Owns | Does not own | Why separate |
|---|---|---|---|---|
| [`app.mts`](app.mts) | Assembly: `createApp` | The order things are built and mounted in; the registries and the built-in `"jwt"` authenticator's registration; the collector bounds the pipelines run under; boot-time refusals and warnings (no rule collector, non-loopback bind without caller auth) | Any request-time behavior — it wires the pieces below and returns | The one place that knows every piece; everything else can be built and tested without it |
| [`index.mts`](index.mts) | Public surface | What the package exports | Implementation — it only re-exports | Anything not listed here (the decision, `createHealthcheckRouter`, `classifyFailure`) stays free to change |
| [`config/`](config/) | Config schema and knob readers | `AppConfigSchema`; `NUMERIC_BOUNDS` and `resolveBound`, the one reader of every numeric knob at both boundaries (#157); defaults; the HS256 entropy measurement; the `oauth.authenticator` and `verify.evaluationInResponse` checks | Using the values — each consumer reads them at its own boundary | Keeps `zod` away from the routers: the schema and the routers share the dependency-light `defaults.mts`, so a config-only consumer does not load the router, and the router does not load the schema |
| [`decision/`](decision/README.md) | One decision without the transport | Running the pipelines, evaluating, sorting a failure into deny or fault, the `decision` line and the counters | The wire, status codes, authentication, config | Has its own [README](decision/README.md); held to a dependency boundary by a test |
| [`http/`](http/) | Transport-level checks outside the decision endpoints | Caller authentication (`http.callerAuth`, #108; mounted by `app.mts` ahead of the router) and the accepted shape of `x-request-id` (#200; applied by the router) | Subject authentication (`jwt/`), routing | Each is exported on its own, so a consumer mounting `createVerifyRouter` on their own app can apply the same gate and the same request-id rule |
| [`jwt/`](jwt/) | Subject authentication | See below | See below | See below |
| [`net/`](net/) | One definition of "loopback" | `isLoopbackHost`, `isLoopbackBindAddress` | — | Two seams ask the question for opposite reasons (the JWKS https exemption, the bind-address warning) and must not drift apart |
| [`observability/`](observability/) | Logging and metrics vocabulary | See below | See below | See below |
| [`routes/`](routes/README.md) | The HTTP endpoints | Body validation, body-before-token, status codes, the deny envelope, the batch lanes, the fault line | The decision itself | Has its own [README](routes/README.md) |

### `jwt/`

The built-in way to turn an `Authorization` header into a subject, and the
server-side contracts for replacing it. It owns the JWT config union
(`VerifyRouterJwtConfig`) and its construction-time checks, the request-time
token checks (signature, RFC 9068 §4 claims, time claims, the `cnf` refusal) in
`tokenAuthenticator.mts`; the key resolvers for HS256 / RS256 / ES256 / EdDSA
and the module that registers them (`builtinKeyResolversModule.mts`); HS256
secret rotation (`hs256Rotation.mts`), JWKS transport policy (`jwks.mts`), the
audience-claim knob (`audienceClaim.mts`); and `JwtTokenAuthenticatorFactory`,
the factory `app.mts` registers as `"jwt"`. It does not own which authenticator
runs (`oauth.authenticator`, read by `config/` and resolved by `app.mts`) or
anything after the subject is established. It is separate because it is the
only code that verifies the subject's credential and the only importer of
`jose`: a
deployment that authenticates another way registers its own
`TokenAuthenticatorFactory` and never runs any of it. The key-resolver
vocabulary lived in core until #170 and moved here for the same reason.

Known issue (#259): the contract types are not separated from
the implementation. `TokenAuthenticator` is declared in `tokenAuthenticator.mts`
beside the JWT implementation, and `ServerModuleContext` and
`TokenAuthenticatorFactory` in `keyResolver.mts`; and
[`routes/verify.mts`](routes/verify.mts) value-imports
`createTokenAuthenticator` from `jwt/`, so the router itself picks the default
authenticator when it is given `jwt`.

### `observability/`

What the server says about its decisions, and in which words. It owns the
`decision` audit line (`decisionEvent.mts`, #111); the closed set of failure
categories, the sorting of a failure into one and the loggable form of an error
(`failure.mts`, #200); the `DecisionMetrics` port — the observation types and
the `countCollectorFailure` helper — (`decisionMetrics.mts`, #258); and the
port's Prometheus implementation — the request histogram middleware, the
`/metrics` router and the decision counters (`metrics.mts`, #111). It does not
own when a line is written or a counter bumped —
[`decision/`](decision/README.md) and [`routes/`](routes/README.md) decide
that — nor where `/metrics` is mounted (`app.mts`), nor what status a failure
category is answered with (`routes/verify.mts`). It is separate so that the log
and metric vocabulary is defined once for the router and the decision alike,
and so that label bounding and redaction are in one place.

The port and its implementation are separate files so that the dependency runs
one way (#258). `decisionMetrics.mts` imports nothing but types from
`failure.mts`, and neither `express` nor `prom-client`, so the decision and the
router report through it without naming the implementation at all;
`metrics.mts` imports the port it implements, and nothing in the directory
imports `metrics.mts` back.

## Dependencies between directories

- `routes/` → `config/`, `decision/`, `http/`, `jwt/`, `observability/`.
- `decision/` → `observability/` only, and through no import — type-only
  included — to `metrics.mts`: it reports through the `decisionMetrics.mts`
  port. Held by
  [`decision/__tests__/dependencies.test.mts`](decision/__tests__/dependencies.test.mts).
- Inside `observability/`: `metrics.mts` → `decisionMetrics.mts` →
  `failure.mts` → `decisionEvent.mts`, with no cycle (type-only imports
  counted); held by the same test. `routes/` imports the port, not
  `metrics.mts`; of the shipped source, only `app.mts` and `index.mts` import
  `metrics.mts`.
- `jwt/` → `config/`, `net/`. `http/` → `config/`.
- `app.mts` → every directory except `decision/`.
- Nothing here imports `app.mts` except `index.mts`.

Known issue (#260): `config/` and `jwt/` import each
other. `config/application.schema.mts` imports the JWT checks from
`jwt/audienceClaim.mts`, `jwt/hs256Rotation.mts` and `jwt/jwks.mts`, while
`jwt/` imports `config/` for bounds, defaults, the entropy check,
`assertConfigObject` and (in `jwtTokenAuthenticatorFactory.mts`) the schema
itself. The file-level graph has no runtime cycle today, but the directories do
not have a direction.
