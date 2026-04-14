// Copyright 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ATTR_CLIENT_IP } from "@o3co/auth.policy-verifier.core";
import type { AttributeCollector, Attributes, CollectorContext } from "@o3co/auth.policy-verifier.core";

export class RequestContextCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		const raw = context.requestContext?.ip;
		if (typeof raw === "string") {
			const ip = raw.trim();
			if (ip) attrs.set(ATTR_CLIENT_IP, ip);
		}
		return attrs;
	}
}
