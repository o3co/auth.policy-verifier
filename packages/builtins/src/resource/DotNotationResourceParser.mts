// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Resource, ResourceParser } from "@o3co/auth.policy-verifier.core";

/**
 * Resource parser for dot-separated, colon-qualified identifiers such as
 * `"org:123.project:abc.document:42"`. Each dot segment is `type[:id]`; the
 * resulting `resourceType` concatenates all segment types with `_`, and
 * `resourceId` is the id of the last segment (if any).
 */
export class DotNotationResourceParser implements ResourceParser {
	parse(raw: string): Resource {
		const segments = raw
			.trim()
			.split(".")
			.map((part) => {
				const [type, id] = part.split(":").map((s) => s.trim());
				return { type, id: id || undefined };
			});

		const resourceType = segments.map((s) => s.type).join("_");
		const resourceId = segments[segments.length - 1].id;

		return { raw, resourceType, resourceId };
	}
}
