// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The shape guard run before indexing into a config block. `createApp` calls it
 * on `oauth` and `http`, the built-in JWT authenticator factory on `oauth` and
 * `oauth.jwt`, for every config, schema-validated or hand-built.
 */

/**
 * Asserts that a config block is an object, so the checks that follow can
 * index into it. A hand-built config never went through `AppConfigSchema` and
 * can put anything at a path; without this the first `in` test or spread throws
 * a bare `TypeError` naming neither the boundary nor the path. Arrays are
 * refused too.
 *
 * `caller` is the boundary the message names: `createApp` by default, which the
 * built-in JWT authenticator factory reports as too, since `createApp` runs it.
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
