// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_CLIENT_ID, ATTR_USER_ID } from "@o3co/auth.policy-verifier.core";

/**
 * Attribute collector that extracts the OAuth/OIDC `sub` and `azp` claims from
 * the subject bag into `ATTR_USER_ID` and `ATTR_CLIENT_ID`. Either claim may
 * be absent.
 *
 * The claim vocabulary lives here, not in core (#170): `SubjectAttributes` is
 * a bag of unknowns, so this collector narrows what it promotes — a claim that
 * is not a non-empty string is not an identity and is left out.
 */
export class PayloadSubjectIdCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		const { sub, azp } = context.subject;
		if (typeof sub === "string" && sub) {
			attrs.set(ATTR_USER_ID, sub);
		}
		if (typeof azp === "string" && azp) {
			attrs.set(ATTR_CLIENT_ID, azp);
		}
		return attrs;
	}
}
