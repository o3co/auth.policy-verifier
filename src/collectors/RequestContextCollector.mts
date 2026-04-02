// Copyright 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ATTR_CLIENT_IP } from "#/engine/keys.mjs";
import type { AttributeCollector, Attributes, CollectorContext } from "#/engine/types.mjs";

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
