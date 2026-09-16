// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The caller's request id, and what it takes for this server to carry one
 * (#200).
 *
 * The decision endpoints read `x-request-id` so a decision can be matched to
 * the enforcing service's own log: it is echoed on the response, put on every
 * failure line and on the `decision` line, and forwarded to collectors on
 * `CollectorContext.headers`. That is four places the caller's text reaches,
 * one of them a response header, so it is accepted only in a shape that cannot
 * reshape any of them.
 *
 * The shape is deliberately a TOKEN, not "printable ASCII". An enforcement
 * layer forwards whatever id it was handed — protobuf.interceptors passes the
 * incoming `x-request-id` through unchanged and only mints its own,
 * `YYYYMMDDHHmmss_<16 hex>`, when there is none — so the constraint cannot be
 * left to the caller. What the charset admits is what real ids are made of:
 * UUIDs and ULIDs, hex trace ids and W3C `traceparent`, base64 and base64url,
 * Kong's `uuid#counter`. What it refuses is everything that means something to
 * a log line or a header: whitespace and line breaks (a forged second line),
 * quotes and braces (a forged JSON field), commas (Node folds two `x-request-id`
 * headers into one comma-joined value, which is two ids, not one), semicolons,
 * `%`, and anything outside ASCII.
 *
 * **Refused means absent.** An id outside the shape is not trimmed, escaped or
 * truncated into something the caller did not send — a correlation key that is
 * not the caller's key correlates with nothing. It is treated exactly as a
 * request that sent none: not echoed, not logged, not forwarded. And the server
 * never mints one in its place, because an id nobody returned to the caller
 * joins nothing either.
 */

/** The header the id is read from and echoed on. */
export const REQUEST_ID_HEADER = "x-request-id";

/**
 * Longest id accepted, in characters. Far above any real format — a UUID is
 * 36, a W3C `traceparent` 55, protobuf.interceptors' own 31 — and short enough
 * that an id cannot make a log line or a response header meaningfully larger.
 */
export const MAX_REQUEST_ID_LENGTH = 128;

/** Letters, digits, and `- _ . : + / = #` — see the module comment for why exactly these. */
const REQUEST_ID_CHARACTERS = /^[A-Za-z0-9\-_.:+/=#]+$/;

/**
 * The request id to carry, or `undefined` when there is none this server will
 * carry: absent, empty, longer than {@link MAX_REQUEST_ID_LENGTH}, or holding a
 * character outside the set above.
 */
export function acceptRequestId(raw: string | undefined): string | undefined {
	if (raw === undefined || raw.length === 0 || raw.length > MAX_REQUEST_ID_LENGTH) {
		return undefined;
	}
	return REQUEST_ID_CHARACTERS.test(raw) ? raw : undefined;
}
