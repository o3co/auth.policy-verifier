# Routes

Last updated: 2026-09-24

## Responsibility

- **Role.** The HTTP surface of the verifier: the decision endpoints
  (`POST /verify`, `POST /verify/batch`) and the liveness route. The decision
  endpoints' entry point is `createVerifyRouter` in [`verify.mts`](verify.mts).
- **Owns.** Everything between the wire and one decision: validating the body
  and holding it to its limits, the order body before token, running the
  authenticator it is handed, turning the caller's disconnect into a signal,
  status codes and headers, the deny envelope on every answer that is not a
  decision, the batch's lanes, what each failure category is answered with,
  and the one fault line a request that could not be decided produces.
- **Does not own.** The decision itself — that is
  [`../decision/`](../decision/README.md), which both decision endpoints call;
  sorting a failure into a category ([`../observability/`](../observability/));
  caller authentication ([`../http/`](../http/)); how the subject is
  authenticated — the contract is [`../auth/`](../auth/), and which
  authenticator runs, the built-in bearer-JWT one included, is decided and
  built by [`../app.mts`](../app.mts) or the consumer mounting the router;
  where the routers are mounted and on which liveness paths
  ([`../app.mts`](../app.mts)).
- **Why a separate module.** Apart from `../app.mts` so the endpoints can be
  mounted without the rest of the assembly — `createVerifyRouter` is public for
  a consumer mounting it on their own Express app; apart from `../decision/` so
  the transport stays out of the decision.

## Invariants

- `createVerifyRouter` and `VerifyRouterConfig` are public, through
  [`../index.mts`](../index.mts); the liveness router is internal. Only
  `../app.mts` and `../index.mts` import this directory.
- Body first, token second: a malformed unauthenticated request is a 400,
  because verifying a token is the half that can reach the network.
- A batch is validated whole before any entry is decided, decided in lanes
  `batchConcurrency` wide, and answered in request order; its status says
  whether it was decided, not what it decided.
- Every answer that is not a decision is the deny envelope
  `{ decision: "deny", code, message }`, the body-parser failures included. The
  handler that ensures it is mounted on the router, so a consumer mounting the
  router on their own app inherits it.
- The router runs the `TokenAuthenticator` it is handed and builds none: it
  depends on the contract in `../auth/`, and reaches `../jwt/` through no
  import at all, type-only included.
- Both config boundaries agree (#157): every numeric knob goes through
  `resolveBound` with the bound `AppConfigSchema` applies. Config the router
  would not honour — a deadline or a failure record in `evaluateOptions`, no
  `authenticator` (`null` included), the removed `jwt` option — is refused at
  construction.
- `x-request-id` is accepted only in the shape `acceptRequestId` admits, echoed
  on every response the router writes, and never minted.
- A timeout or an attribute conflict is a deny carrying that code; any other
  failure is a 500 with one fault line (`verify_internal_error`) per request, a
  batch included. The caller's own abort is `verify_caller_gone`: no fault line
  and no 500.

Pinned by the router tests in [`../__tests__/`](../__tests__/) — chiefly
[`verify.test.mts`](../__tests__/verify.test.mts),
[`verifyInputValidation.test.mts`](../__tests__/verifyInputValidation.test.mts),
[`failureTriage.test.mts`](../__tests__/failureTriage.test.mts) and
[`requestId.test.mts`](../__tests__/requestId.test.mts) — and, for the wire
shape, by the cross-implementation contract in
[`tests/integration/src/conformance/wireContract.mts`](../../../../tests/integration/src/conformance/wireContract.mts).

## Dependencies

- May import `express`, `@o3co/auth.policy-verifier.core`,
  [`../auth/`](../auth/) (types only), [`../config/`](../config/),
  [`../decision/`](../decision/README.md), [`../http/`](../http/) and
  [`../observability/`](../observability/).
- Must not reach [`../jwt/`](../jwt/) or jose, directly or through anything it
  imports; pinned by
  [`../decision/__tests__/dependencies.test.mts`](../decision/__tests__/dependencies.test.mts).
- Reports metrics through the `DecisionMetrics` port, never the Prometheus
  implementation.
