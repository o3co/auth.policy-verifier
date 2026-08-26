// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The engine-neutral request shape every conformance suite is written against.
 *
 * `(subject, resource, action, context)` is deliberately a superset of what any
 * one engine needs: OPA takes an input document, OpenFGA takes
 * `check(user, relation, object)`, Cedar takes a principal/action/resource
 * quadruple. A contract carrying all four can be satisfied by an adapter for any
 * of them, which is what makes a later engine change a swap rather than a
 * rewrite. Baking a narrower shape — scope-only, say — into the wire is exactly
 * what would force the rewrite.
 */
export interface AuthorizationRequest {
	subject: string;
	resource: string;
	action: string;
	context?: Record<string, unknown>;
}
