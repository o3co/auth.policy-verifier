import type { Resource, ResourceParser } from "@o3co/auth.policy-verifier.core";

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
