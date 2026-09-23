# Server source map

Last updated: 2026-09-23

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

Known issue, not yet tracked in an issue: the contract types are not separated from
the implementation. `TokenAuthenticator` is declared in `tokenAuthenticator.mts`
beside the JWT implementation, and `ServerModuleContext` and
`TokenAuthenticatorFactory` in `keyResolver.mts`; and
[`routes/verify.mts`](routes/verify.mts) value-imports
`createTokenAuthenticator` from `jwt/`, so the router itself picks the default
authenticator when it is given `jwt`.

### `observability/`

What the server says about its decisions, and in which words. It owns the
`decision` audit line (`decisionEvent.mts`, #111); the closed set of failure
categories, the sorting of a failure into one, the loggable form of an error
and the collector-failure counter helper (`failure.mts`, #200); and the
`DecisionMetrics` seam with its Prometheus implementation — the request
histogram middleware, the `/metrics` router and the decision counters
(`metrics.mts`, #111). It does not own when a line is written or a counter
bumped — [`decision/`](decision/README.md) and [`routes/`](routes/README.md)
decide that — nor where `/metrics` is mounted (`app.mts`). It is separate so
that the log and metric vocabulary is defined once for the router and the
decision alike, and so that label bounding and redaction are in one place.

Known issues, not yet tracked in an issue: `metrics.mts` holds both the
`DecisionMetrics` port and its `prom-client` / `express` implementation, so the
decision may import only its type — which is why `countCollectorFailure` lives
in `failure.mts` rather than beside the port. `failure.mts` and `metrics.mts`
import each other's types (`DecisionMetrics` one way,
`CollectorFailureCategory` the other): a type-only cycle, erased at runtime.
`failure.mts` also documents the HTTP status each category is answered with,
which is the router's concern.

## Dependencies between directories

- `routes/` → `config/`, `decision/`, `http/`, `jwt/`, `observability/`.
- `decision/` → `observability/` only (value imports stop short of
  `metrics.mts`); held by
  [`decision/__tests__/dependencies.test.mts`](decision/__tests__/dependencies.test.mts).
- `jwt/` → `config/`, `net/`. `http/` → `config/`.
- `app.mts` → every directory except `decision/`.
- Nothing here imports `app.mts` except `index.mts`.

Known issue, not yet tracked in an issue: `config/` and `jwt/` import each
other. `config/application.schema.mts` imports the JWT checks from
`jwt/audienceClaim.mts`, `jwt/hs256Rotation.mts` and `jwt/jwks.mts`, while
`jwt/` imports `config/` for bounds, defaults, the entropy check,
`assertConfigObject` and (in `jwtTokenAuthenticatorFactory.mts`) the schema
itself. The file-level graph has no runtime cycle today, but the directories do
not have a direction.
