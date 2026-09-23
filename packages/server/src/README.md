# Server source map

Last updated: 2026-09-24

## Responsibility

- **Role.** `src/` is the whole of `@o3co/auth.policy-verifier.server`: the
  assembly that turns config and modules into an Express app, and one directory
  per concern beneath it. How to use the package is in the
  [package README](../README.md).
- **Owns.** The two entry points and the directories in the map below.
  [`app.mts`](app.mts) (`createApp`) is the assembly — the one place that knows
  every piece and the order they are built and mounted in; everything else can
  be built and tested without it. [`index.mts`](index.mts) is the public
  surface: consumers import only through it, and anything it does not export
  stays free to change.
- **Does not own.** Evaluation semantics, the collector and rule contracts,
  concrete collectors, the process lifecycle — see the
  [package README](../README.md#responsibility).
- **Why a separate module.** It is the package; why the server is a package of
  its own is in the [package README](../README.md#responsibility).

## Map

| Directory | Role | Owns | Does not own | Why separate |
|---|---|---|---|---|
| [`auth/`](auth/) | The subject-authentication contract | The `TokenAuthenticator` port and its result, the factory a module registers one through and what the host hands that factory, the key-resolver vocabulary, and `ServerModuleContext` | Any implementation — the built-in one is `jwt/`; which authenticator runs (`oauth.authenticator`, read by `config/` and resolved by `app.mts`) | A deployment that authenticates another way, and the router that runs whichever authenticator it is handed, depend on the contract without loading `jwt/` or jose |
| [`config/`](config/) | Config schema and knob readers | `AppConfigSchema`, the defaults, and the bounds and checks both config boundaries read a knob through (#157) — the JWT block's among them (audience claim, HS256 rotation, JWKS URI) | Using the values — each consumer reads them at its own boundary | Keeps `zod` out of the routers: a config-only consumer does not load the router, and the router does not load the schema |
| [`decision/`](decision/README.md) | One decision without the transport | Running the pipelines, evaluating, sorting a failure into a deny or a fault, reporting the decision | The wire, status codes, authentication, config | Held to a dependency boundary the router cannot be — see its [README](decision/README.md) |
| [`http/`](http/) | Transport-level checks outside the decision endpoints | Caller authentication and the accepted shape of `x-request-id` | Subject authentication (`auth/`, `jwt/`), routing | Each is exported on its own, so a consumer mounting `createVerifyRouter` on their own app can apply the same gate and the same request-id rule |
| [`jwt/`](jwt/) | The built-in subject authentication | The bearer-JWT implementation of `auth/`'s contract: the authenticator, its construction-time guard, the built-in `"jwt"` factory, and the key resolvers | The contract (`auth/`); the config checks it shares with the schema (`config/`); which authenticator runs; anything after the subject is established | The only code that verifies a JWT: a deployment that authenticates another way registers its own `TokenAuthenticatorFactory` and runs none of it |
| [`net/`](net/) | One definition of "loopback" | The loopback-host and loopback-bind-address predicates | — | Two seams ask the question for opposite reasons (the JWKS https exemption, the bind-address warning) and must not drift apart |
| [`observability/`](observability/) | Logging and metrics vocabulary | The `decision` audit line; the closed set of failure categories, the sorting into them and the loggable form of an error; the `DecisionMetrics` port and its Prometheus implementation | When a line is written or a counter bumped (`decision/`, `routes/`); where `/metrics` is mounted (`app.mts`); what status a failure category is answered with (`routes/`) | The log and metric vocabulary is defined once for the router and the decision alike, with label bounding and redaction in one place |
| [`routes/`](routes/README.md) | The HTTP endpoints | Body validation, body before token, status codes, the deny envelope, the batch lanes, the fault line | The decision itself | Mountable without the rest of the assembly — see its [README](routes/README.md) |

## Invariants

- Nothing imports `app.mts` except `index.mts`.
- Each runtime dependency beyond core is confined to fixed places: `jose` to
  `jwt/`, `zod` to `config/`, `prom-client` to `observability/`, and `express`
  to `app.mts`, `routes/`, `observability/` and (type-only) `http/`.
- `auth/` is the authentication contract and imports no implementation: it
  reaches core's types and nothing else, type-only imports counted. `jwt/`
  implements it.
- The router runs the authenticator it is handed and builds none: `routes/`
  reaches `jwt/` through no import at all, type-only included. The default
  bearer-JWT authenticator is built by `app.mts`.
- `jwt/` depends on `config/` and never the reverse: `config/` reaches `jwt/`
  through no import, type-only included. A check both the schema and the JWT
  path read lives in `config/`.
- The decision and the router report metrics through the `DecisionMetrics`
  port (`observability/decisionMetrics.mts`), never the Prometheus
  implementation; of the shipped source only `app.mts` and `index.mts` import
  the implementation.
- `observability/` has no import cycle, type-only imports counted.

The decision's boundary, the `observability/` cycle rule and the three
directions above are pinned by
[`decision/__tests__/dependencies.test.mts`](decision/__tests__/dependencies.test.mts).

## Dependencies

- `routes/` → `auth/` (type-only), `config/`, `decision/`, `http/`,
  `observability/`.
- `decision/` → `observability/` only, and to no other directory through
  anything it imports.
- `jwt/` → `auth/`, `config/`.
- `config/` → `net/`.
- `http/` → `config/`.
- `auth/`, `net/` and `observability/` → no other directory.
- `app.mts` → every directory except `decision/`.
