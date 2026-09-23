# Routes

Last updated: 2026-09-24

The HTTP surface of the verifier: the decision endpoints and the liveness
route.

## Responsibility

[`verify.mts`](verify.mts) owns everything between the wire and one decision:
validating the body (its shape, the five limits, unknown properties, the
resource grammar — #118), the order body-before-token, authenticating the
subject, turning the caller's disconnect into a signal, choosing status codes
and headers, the deny envelope on every answer that is not a decision, the
batch's lanes, and the one fault line a request that could not be decided
produces. It does not decide: that is [`../decision/`](../decision/), which
both routes call.

[`healthcheck.mts`](healthcheck.mts) answers liveness on the path `createApp`
mounts it at, with no dependency on the decision.

The router also chooses the default authenticator: given `jwt` rather than an
`authenticator`, `createVerifyRouter` builds the built-in bearer-JWT one itself
(`createTokenAuthenticator`, a value import from
[`../jwt/tokenAuthenticator.mts`](../jwt/tokenAuthenticator.mts)). So the router
depends on the JWT implementation, not only on the `TokenAuthenticator`
contract; moving that contract out of `../jwt/` is tracked in #259 (see
[`../README.md`](../README.md)).

It is separate from [`../app.mts`](../app.mts) so that the endpoints can be
mounted without the rest of the assembly — `createVerifyRouter` is public for a
consumer mounting it on their own Express app — and separate from
`../decision/` so that the transport stays out of the decision.

## Public contract

- [`createVerifyRouter(config)`](verify.mts) and `VerifyRouterConfig`, exported
  from [`../index.mts`](../index.mts). The wire types `DecisionRequest` and
  `DecisionResponse` are re-exported from here.
- `createHealthcheckRouter(path)` — internal: not exported from
  `../index.mts`; only [`../app.mts`](../app.mts) uses it.

## Inputs and outputs

- The body is the caller's: validated once, bounded by the limits the config
  resolves, unknown properties refused (#118). A `resource` the configured
  parser refuses is a 400, not a fault.
- `Authorization` is the authenticator's to read; the router only passes it on.
- `x-request-id` is accepted only in the shape `acceptRequestId` admits, echoed
  on every response the router writes, and never minted (#200).
- Every answer that is not a decision is the deny envelope
  `{ decision: "deny", code, message }`, the body-parser failures included, so a
  caller that parses only decision JSON is never handed an HTML error page.

## Dependencies

`express`, [`../config/`](../config/) (`resolveBound`, the evaluation-in-response
check), [`../decision/`](../decision/), [`../http/`](../http/),
[`../jwt/`](../jwt/) (the `TokenAuthenticator` and `VerifyRouterJwtConfig` types and, for the
default path, `createTokenAuthenticator`) and [`../observability/`](../observability/).
Only [`../app.mts`](../app.mts) and the public index import this directory.

## Invariants

- Body first, token second (#118): a malformed unauthenticated request is a
  400, because verifying a token is the half that can reach the network.
- A batch is validated whole before any entry is decided, decided in lanes
  `batchConcurrency` wide (#183), and answered in request order; its status
  says whether it was decided, not what it decided.
- Both boundaries agree (#157): every numeric knob goes through `resolveBound`
  with the same bound `AppConfigSchema` applies, and a deadline or a failure
  record smuggled in through `evaluateOptions` is refused at construction.
- Exactly one of `jwt` and `authenticator` (#219); `null` for either is refused
  by name rather than read as omitted.
- One fault line (`verify_internal_error`) per request, carrying the category
  and, where there is one, the collector or rule; the caller's own abort is
  `verify_caller_gone` and no 500.

## Failure and lifecycle

- 400 malformed body or resource, 401 authentication, 413 body over
  `maxBodyBytes`, 415 unreadable content type, 500 anything unexpected; the
  body-parser failures reach the envelope through `denyOnBodyFailure`, mounted
  on the router so a consumer mounting it on their own app inherits it.
- A decision that could not be made is answered by the failure category
  [`../observability/failure.mts`](../observability/failure.mts) sorts it into:
  a timeout or an attribute conflict is a deny carrying that code, anything
  else a 500. The per-category answers are written on `createVerifyRouter` in
  [`verify.mts`](verify.mts); `failure.mts` only sorts (#258).
- `callerSignal` aborts the decision when the response closes before it was
  finished; what is already in flight settles on its own, a batch's lanes start
  no further entry, and the route writes `verify_caller_gone` and no fault line.

## Contract tests

[`../__tests__/verify.test.mts`](../__tests__/verify.test.mts),
[`../__tests__/verifyInputValidation.test.mts`](../__tests__/verifyInputValidation.test.mts),
[`../__tests__/verifyLogging.test.mts`](../__tests__/verifyLogging.test.mts),
[`../__tests__/failureTriage.test.mts`](../__tests__/failureTriage.test.mts),
[`../__tests__/requestId.test.mts`](../__tests__/requestId.test.mts),
[`../__tests__/metrics.test.mts`](../__tests__/metrics.test.mts),
[`../__tests__/decisionLogging.test.mts`](../__tests__/decisionLogging.test.mts),
[`../__tests__/evaluationProvenance.test.mts`](../__tests__/evaluationProvenance.test.mts),
and the cross-implementation wire contract in
[`../../../../tests/integration/src/conformance/wireContract.mts`](../../../../tests/integration/src/conformance/wireContract.mts).
