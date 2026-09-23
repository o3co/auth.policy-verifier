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
| [`config/`](config/) | Config schema and knob readers | `AppConfigSchema`, the defaults, and the bounds and checks both config boundaries read a knob through (#157) | Using the values — each consumer reads them at its own boundary | Keeps `zod` out of the routers: a config-only consumer does not load the router, and the router does not load the schema |
| [`decision/`](decision/README.md) | One decision without the transport | Running the pipelines, evaluating, sorting a failure into a deny or a fault, reporting the decision | The wire, status codes, authentication, config | Held to a dependency boundary the router cannot be — see its [README](decision/README.md) |
| [`http/`](http/) | Transport-level checks outside the decision endpoints | Caller authentication and the accepted shape of `x-request-id` | Subject authentication (`jwt/`), routing | Each is exported on its own, so a consumer mounting `createVerifyRouter` on their own app can apply the same gate and the same request-id rule |
| [`jwt/`](jwt/) | Subject authentication | The built-in bearer-JWT authenticator and its config checks, the key resolvers, and the server-side contracts for replacing the authenticator | Which authenticator runs (`oauth.authenticator`, read by `config/` and resolved by `app.mts`); anything after the subject is established | The only code that verifies the subject's credential: a deployment that authenticates another way registers its own `TokenAuthenticatorFactory` and runs none of it |
| [`net/`](net/) | One definition of "loopback" | The loopback-host and loopback-bind-address predicates | — | Two seams ask the question for opposite reasons (the JWKS https exemption, the bind-address warning) and must not drift apart |
| [`observability/`](observability/) | Logging and metrics vocabulary | The `decision` audit line; the closed set of failure categories, the sorting into them and the loggable form of an error; the `DecisionMetrics` port and its Prometheus implementation | When a line is written or a counter bumped (`decision/`, `routes/`); where `/metrics` is mounted (`app.mts`); what status a failure category is answered with (`routes/`) | The log and metric vocabulary is defined once for the router and the decision alike, with label bounding and redaction in one place |
| [`routes/`](routes/README.md) | The HTTP endpoints | Body validation, body before token, status codes, the deny envelope, the batch lanes, the fault line | The decision itself | Mountable without the rest of the assembly — see its [README](routes/README.md) |

## Invariants

- Nothing imports `app.mts` except `index.mts`.
- Each runtime dependency beyond core is confined to fixed places: `jose` to
  `jwt/`, `zod` to `config/`, `prom-client` to `observability/`, and `express`
  to `app.mts`, `routes/`, `observability/` and (type-only) `http/`.
- The decision and the router report metrics through the `DecisionMetrics`
  port (`observability/decisionMetrics.mts`), never the Prometheus
  implementation; of the shipped source only `app.mts` and `index.mts` import
  the implementation.
- `observability/` has no import cycle, type-only imports counted.

The decision's boundary and the `observability/` cycle rule are pinned by
[`decision/__tests__/dependencies.test.mts`](decision/__tests__/dependencies.test.mts).

## Dependencies

- `routes/` → `config/`, `decision/`, `http/`, `jwt/`, `observability/`.
- `decision/` → `observability/` only, and to no other directory through
  anything it imports.
- `jwt/` → `config/`, `net/`.
- `config/` → `jwt/` (see Known issues).
- `http/` → `config/`.
- `net/` and `observability/` → no other directory.
- `app.mts` → every directory except `decision/`.

## Known issues

- [#259](https://github.com/o3co/auth.policy-verifier/issues/259) — the
  authenticator contract types live in `jwt/`'s implementation files, and
  `routes/` picks the default authenticator, so it depends on the JWT
  implementation.
- [#260](https://github.com/o3co/auth.policy-verifier/issues/260) — `config/`
  and `jwt/` import each other, so the two directories have no direction.
