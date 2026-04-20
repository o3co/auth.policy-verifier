// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_CLIENT_ID, ATTR_USER_ID } from "@o3co/auth.policy-verifier.core";

/**
 * Attribute collector that extracts `sub` and `azp` from the JWT payload into
 * `ATTR_USER_ID` and `ATTR_CLIENT_ID`. Either claim may be absent.
 */
export class PayloadSubjectIdCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		if (context.payload.sub) {
			attrs.set(ATTR_USER_ID, context.payload.sub);
		}
		if (context.payload.azp) {
			attrs.set(ATTR_CLIENT_ID, context.payload.azp);
		}
		return attrs;
	}
}
