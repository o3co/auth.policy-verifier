// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Which `http.callerAuth` values a request can present. A header name or a
 * credential no request can carry does not fail at run time: every request is
 * refused, so a deployment boots into answering nothing. Each check below
 * refuses such a value at boot instead.
 *
 * What a request can carry is Node's HTTP parser's to say. It strips the
 * spaces and tabs around a header value (RFC 9110 §5.5), refuses a request
 * whose header value holds a control character other than a tab, and reads a
 * header name only as an RFC 9110 §5.6.2 token.
 *
 * Dependency-free: `AppConfigSchema` and the runtime guards in
 * `http/callerAuth.mts` read the same verdict through it (AGENTS.md,
 * "Two-Boundary Config Validation"). It lives in `config/` so the dependency
 * runs one way, `http/` → `config/`.
 */

/** The verdict on a caller-auth field: the value to use, or why it is refused. */
export type CallerAuthFieldCheck = { ok: true; value: string } | { ok: false; message: string };

/** RFC 9110 §5.6.2: `token = 1*tchar`. */
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** True when `value` holds a character no header value can carry: a control character other than a tab. */
function hasControlCharacter(value: string): boolean {
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		if ((code < 0x20 && code !== 0x09) || code === 0x7f) return true;
	}
	return false;
}

/**
 * Checks `http.callerAuth.token`, the credential a caller presents verbatim.
 * The message names the key relative to the `callerAuth` block; the runtime
 * guard prefixes its own path.
 */
export function checkCallerAuthToken(value: unknown): CallerAuthFieldCheck {
	if (typeof value !== "string" || value === "") {
		return { ok: false, message: "token must be a non-empty string" };
	}
	if (/^[ \t]|[ \t]$/.test(value)) {
		return {
			ok: false,
			message:
				"token must not begin or end with a space or tab: HTTP strips them from a header value, so no request can present it",
		};
	}
	if (hasControlCharacter(value)) {
		return {
			ok: false,
			message:
				"token must not contain a control character, a trailing newline included: no request can carry one in a header value",
		};
	}
	return { ok: true, value };
}

/**
 * Checks `http.callerAuth.header`, the name of the header carrying the
 * credential. The message names the key relative to the `callerAuth` block;
 * the runtime guard prefixes its own path.
 */
export function checkCallerAuthHeader(value: unknown): CallerAuthFieldCheck {
	if (typeof value !== "string" || value === "") {
		return { ok: false, message: "header must be a non-empty string" };
	}
	if (!TOKEN.test(value)) {
		return {
			ok: false,
			message:
				"header must be an HTTP field name, RFC 9110 token characters only: no request carries a header named otherwise",
		};
	}
	return { ok: true, value };
}
