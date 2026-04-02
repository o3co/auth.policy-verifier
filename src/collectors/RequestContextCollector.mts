// Copyright 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ATTR_CLIENT_IP } from "#/engine/keys.mjs";
import type { AttributeCollector, Attributes, CollectorContext } from "#/engine/types.mjs";

export class RequestContextCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		const ip = context.requestContext?.ip;
		if (typeof ip === "string" && ip.trim()) {
			attrs.set(ATTR_CLIENT_IP, ip.trim());
		}
		return attrs;
	}
}
