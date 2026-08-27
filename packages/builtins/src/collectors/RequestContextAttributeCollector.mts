// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";

/** Types a `requestContext` field may be promoted as. */
export type RequestContextAttributeType = "string" | "number" | "boolean" | "string[]";

const ATTRIBUTE_TYPES: readonly RequestContextAttributeType[] = [
	"string",
	"number",
	"boolean",
	"string[]",
];

/** One field this collector promotes out of `requestContext`. */
export interface RequestContextAttributeMapping {
	/** Field to read, as a dot path (`"tenant.id"`) into `requestContext`. */
	from: string;
	/** Attribute key to write. Defaults to `from`. */
	to?: string;
	/** Expected type; a value of any other shape is not promoted. Defaults to `"string"`. */
	type?: RequestContextAttributeType;
}

/** Config entry accepted by `RequestContextAttributeCollector`. */
export interface RequestContextAttributeCollectorConfig {
	/** The fields to promote. Must declare at least one. */
	attributes: RequestContextAttributeMapping[];
}

/**
 * Promotes declared fields of `CollectorContext.requestContext` into attributes.
 *
 * `requestContext` is the free-form container the transport fills in, and until
 * now nothing built-in consumed it: any environment or relationship attribute
 * meant writing a bespoke collector, even for the common case of "read this
 * field, check its type, write it under this key".
 *
 * Core deliberately assumes no shape for `requestContext` and keeps its `ATTR_*`
 * vocabulary to OAuth/OIDC/RBAC standards, so this collector invents no
 * vocabulary either: the operator declares which fields to read and what to call
 * them, and nothing undeclared is promoted. That declaration is also the trust
 * boundary — `requestContext` is caller-supplied and unvalidated, so a field the
 * config did not name cannot reach a rule, and one whose value does not match
 * its declared type is dropped rather than passed along.
 *
 * ```hocon
 * { collector = "RequestContextAttributeCollector"
 *   attributes = [
 *     { from = "tenant.id", to = "tenantId" }
 *     { from = "groups", type = "string[]" }
 *   ] }
 * ```
 */
export class RequestContextAttributeCollector implements AttributeCollector {
	private readonly mappings: Required<RequestContextAttributeMapping>[];

	constructor(config: RequestContextAttributeCollectorConfig) {
		const attributes = config?.attributes;
		if (!Array.isArray(attributes) || attributes.length === 0) {
			throw new Error(
				"RequestContextAttributeCollector: attributes must be a non-empty array of mappings",
			);
		}
		this.mappings = attributes.map((mapping, index) => {
			const { from, to, type = "string" } = mapping ?? {};
			if (typeof from !== "string" || from === "") {
				throw new Error(
					`RequestContextAttributeCollector: attributes[${index}].from must be a non-empty string`,
				);
			}
			if (to !== undefined && (typeof to !== "string" || to === "")) {
				throw new Error(
					`RequestContextAttributeCollector: attributes[${index}].to must be a non-empty string`,
				);
			}
			if (!ATTRIBUTE_TYPES.includes(type)) {
				throw new Error(
					`RequestContextAttributeCollector: attributes[${index}].type must be one of ${ATTRIBUTE_TYPES.join(", ")}, got "${type}"`,
				);
			}
			return { from, to: to ?? from, type };
		});
	}

	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		const requestContext = context.requestContext;
		if (requestContext === undefined || requestContext === null) return attrs;

		for (const mapping of this.mappings) {
			const raw = readPath(requestContext, mapping.from);
			if (matchesType(raw, mapping.type)) {
				attrs.set(mapping.to, Array.isArray(raw) ? [...raw] : raw);
			}
		}
		return attrs;
	}
}

/**
 * Reads a dot path, traversing own properties only. `requestContext` is
 * caller-supplied, so inherited members (`constructor`, `toString`, …) must not
 * be reachable through a configured path.
 */
function readPath(root: Record<string, unknown>, path: string): unknown {
	let current: unknown = root;
	for (const segment of path.split(".")) {
		if (typeof current !== "object" || current === null) return undefined;
		if (!Object.hasOwn(current, segment)) return undefined;
		current = (current as Record<string, unknown>)[segment];
	}
	return current;
}

/** Whether `value` is usable as the declared type. Empty strings count as absent. */
function matchesType(value: unknown, type: RequestContextAttributeType): boolean {
	switch (type) {
		case "string":
			return typeof value === "string" && value !== "";
		case "number":
			return typeof value === "number" && Number.isFinite(value);
		case "boolean":
			return typeof value === "boolean";
		case "string[]":
			return Array.isArray(value) && value.every((item) => typeof item === "string" && item !== "");
	}
}
