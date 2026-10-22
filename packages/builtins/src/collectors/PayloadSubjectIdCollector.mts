// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The attribute collector that promotes the `sub` claim into `ATTR_USER_ID`,
 * and the client named by `client_id` and `azp` into `ATTR_CLIENT_ID`.
 */

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_CLIENT_ID, ATTR_USER_ID } from "@o3co/auth.policy-verifier.core";

/**
 * Attribute collector that extracts the OAuth/OIDC subject and client from
 * the subject bag: `sub` into `ATTR_USER_ID`, and `client_id` and `azp` into
 * `ATTR_CLIENT_ID`. Any of them may be absent.
 *
 * The client has two spellings, and neither outranks the other. An RFC 9068
 * access token names it in `client_id` (RFC 9068 §2.2, RFC 8693 §4.3); OIDC
 * Core §2 has `azp` carry the client id of the party a token was issued to.
 * The client is promoted when every one of the two the token carries is
 * a non-empty string and they name the same client. When they differ, or one
 * is present with any other value, the token does not say which client it is,
 * and `ATTR_CLIENT_ID` stays unset rather than guessed.
 *
 * The claim vocabulary lives here, not in core: `SubjectAttributes` is
 * a bag of unknowns, so this collector narrows what it promotes — a claim that
 * is not a non-empty string is not an identity and is left out.
 */
export class PayloadSubjectIdCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		const { sub, client_id, azp } = context.subject;
		if (isIdentity(sub)) {
			attrs.set(ATTR_USER_ID, sub);
		}
		const clientId = clientOf(client_id, azp);
		if (clientId !== undefined) {
			attrs.set(ATTR_CLIENT_ID, clientId);
		}
		return attrs;
	}
}

const isIdentity = (value: unknown): value is string => typeof value === "string" && value !== "";

/** The one client the present claims agree on, or undefined when they name none or disagree. */
function clientOf(...claims: readonly unknown[]): string | undefined {
	const present = claims.filter((claim) => claim !== undefined);
	const [first] = present;
	if (!isIdentity(first)) return undefined;
	return present.every((claim) => claim === first) ? first : undefined;
}
