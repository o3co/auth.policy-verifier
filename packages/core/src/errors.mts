// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Raised by a {@link ResourceParser} when the resource string does not belong
 * to the syntax it parses.
 *
 * A parser that cannot read its input has two options: guess, or refuse.
 * Guessing is what makes distinct resources collide into one authorization
 * namespace — the derived `resourceType` is what scope rules authorize, so a
 * parser that silently repairs its input can hand a caller a grant that was
 * written for a different resource. Refusing keeps the failure at the edge,
 * where it is a malformed request rather than a wrong decision.
 *
 * This is a **request** error, not a server error: the transport layer should
 * answer it as a 400-class response naming the offending string, the same as
 * any other unusable field of the request body.
 */
export class ResourceParseError extends Error {
	constructor(
		/** The resource string that was refused, verbatim. */
		readonly raw: string,
		/** Why it was refused, phrased for the caller who sent it. */
		readonly detail: string,
	) {
		super(`Invalid resource string "${raw}": ${detail}`);
		this.name = "ResourceParseError";
	}
}
