// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Brand key carrying the caller-supplied record. Deliberately not exported: it
 * is what makes {@link UntrustedRequestContext} opaque, so the accessor below is
 * the only way in.
 *
 * `Symbol.for` rather than `Symbol()` so two copies of this package in one
 * dependency tree agree on the key — a context marked by the copy the server
 * resolved must still be readable by the copy a collector resolved.
 */
const UNTRUSTED_REQUEST_CONTEXT: unique symbol = Symbol.for(
	"@o3co/auth.policy-verifier.core#untrustedRequestContext",
);

/**
 * Caller-supplied request context, sealed so it cannot be read by accident.
 *
 * The request body's `context` is attacker-controlled: whoever holds a token can
 * put anything in it. It reaches every collector alongside claims that a
 * signature vouches for, and nothing about a plain `Record<string, unknown>`
 * told the two apart — a collector promoting `requestContext.role` into an
 * attribute reads exactly like one promoting `payload.sub`, and the caller has
 * then written its own authorization input.
 *
 * So the type does the telling. The record hangs off a private symbol, which
 * makes `context.requestContext.role` a compile error: an author who wants the
 * value calls {@link readUntrustedRequestContext} and names the trust level at
 * the point of use. That is the whole guarantee — the framework cannot know
 * which fields a deployment may trust, but it can refuse to let one be consumed
 * without saying so out loud.
 *
 * Verified input stays where it was: `payload` (signature-checked claims),
 * `resource` and `action` (validated by the route), `headers` (set by the
 * transport). Only this one field is marked, because only this one is the
 * caller's to fill.
 */
export interface UntrustedRequestContext {
	readonly [UNTRUSTED_REQUEST_CONTEXT]: Record<string, unknown>;
}

/**
 * Marks a caller-supplied record as untrusted. Called by the transport that
 * received it — the verify route for this repo's server, or a consuming
 * project's own interceptor when it builds a `CollectorContext` by hand.
 */
export function markUntrustedRequestContext(raw: Record<string, unknown>): UntrustedRequestContext {
	return { [UNTRUSTED_REQUEST_CONTEXT]: raw };
}

/**
 * Unwraps a marked request context, acknowledging that everything inside it is
 * caller-supplied and unvalidated. Returns `undefined` when the request carried
 * no context, so a collector's `?.` chain reads the same as before.
 *
 * Validate every field you read: check its type, check its shape, and promote
 * only what your policy is prepared to have an attacker choose. A value taken
 * from here must never be treated as an identity or an entitlement.
 */
export function readUntrustedRequestContext(
	context: UntrustedRequestContext | undefined,
): Record<string, unknown> | undefined {
	return context?.[UNTRUSTED_REQUEST_CONTEXT];
}
