/**
 * Example: REST-based role collector.
 *
 * Fetches roles from an external REST API.
 * Copy this file into your project and modify to match your API.
 */
import type { Attributes, AttributeCollector, CollectorContext, Role } from "@o3co/auth.policy-verifier";
import { ATTR_ROLES } from "@o3co/auth.policy-verifier";

export class SampleRestRoleCollector implements AttributeCollector {
	private endpointUrl: string;
	private timeout: number;

	constructor(config: { endpointUrl: string; timeout?: number }) {
		this.endpointUrl = config.endpointUrl;
		this.timeout = config.timeout ?? 3000;
	}

	async collect(context: CollectorContext): Promise<Attributes> {
		const userId = (context.payload as any).user?.id;
		if (!userId) return new Map();

		try {
			const url = new URL(this.endpointUrl);
			url.searchParams.set("userId", userId);
			url.searchParams.set("resource", context.resource.raw);

			const res = await fetch(url, {
				signal: AbortSignal.timeout(this.timeout),
				headers: context.headers,
			});

			if (!res.ok) return new Map([[ATTR_ROLES, []]]);

			const data = (await res.json()) as { roles: Role[] };
			return new Map([[ATTR_ROLES, data.roles ?? []]]);
		} catch {
			return new Map([[ATTR_ROLES, []]]);
		}
	}
}
