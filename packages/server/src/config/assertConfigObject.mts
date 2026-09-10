// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Asserts that a config block a hand-built config supplies is actually an
 * object, so the checks that follow can index into it. `createApp` accepts
 * config objects that never went through `AppConfigSchema`, and a JavaScript
 * caller can put anything at a given path; without this the first `in` test or
 * object spread throws a bare `TypeError` naming neither the boundary nor the
 * path the operator wrote. Arrays are rejected too: indexable, but never a
 * valid config block.
 *
 * `caller` is the boundary named in the message — `createApp` by default,
 * which is also what the built-in JWT authenticator factory reports as, since
 * `createApp` is the boundary that runs it.
 */
export function assertConfigObject(
	value: unknown,
	path: string,
	caller = "createApp",
): asserts value is Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error(
			`${caller}: ${path} must be a config object, got ${value === null ? "null" : Array.isArray(value) ? "array" : typeof value}`,
		);
	}
}
