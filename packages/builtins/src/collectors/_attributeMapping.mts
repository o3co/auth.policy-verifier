// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The declaration shape two collectors share (#219): an operator names the
 * fields to promote, what to call them, and what type each must have.
 * `RequestContextAttributeCollector` reads them out of the caller's request
 * body; `PayloadClaimAttributeCollector` reads them out of the verified
 * subject bag. What differs between the two is the source and therefore the
 * trust — which is why the reserved-key policy is the caller's to supply, not
 * something this module decides.
 */

import type { AttributeKeyReservation, Attributes } from "@o3co/auth.policy-verifier.core";
import { attributeKeyReservation } from "@o3co/auth.policy-verifier.core";

/** Types a field may be promoted as. */
export type AttributeMappingType = "string" | "number" | "boolean" | "string[]";

export const ATTRIBUTE_MAPPING_TYPES: readonly AttributeMappingType[] = [
	"string",
	"number",
	"boolean",
	"string[]",
];

/** One field to promote. */
export interface AttributeMapping {
	/**
	 * Field to read. An exact key on the source wins; otherwise a dot path
	 * (`"tenant.id"`) is walked — so a claim whose *name* carries dots, such as
	 * Auth0's `https://example.com/roles`, is one key, not a path.
	 */
	from: string;
	/** Attribute key to write. Defaults to `from`. */
	to?: string;
	/** Expected type; a value of any other shape is not promoted. Defaults to `"string"`. */
	type?: AttributeMappingType;
}

/** Config entry shape shared by the mapping collectors. */
export interface AttributeMappingCollectorConfig {
	/** The fields to promote. Must declare at least one. */
	attributes: AttributeMapping[];
}

export type ResolvedAttributeMapping = Required<AttributeMapping>;

/**
 * What a collector decides about a mapping onto a reserved key: the refusal
 * to throw, or `undefined` to allow it. Called only for reserved destinations.
 */
export type ReservedKeyPolicy = (
	index: number,
	reservation: AttributeKeyReservation,
) => string | undefined;

/**
 * Validates the declaration at construction — boot, not first request — so a
 * deployment that wrote a malformed or refused mapping never serves a decision.
 */
export function parseAttributeMappings(
	collector: string,
	config: AttributeMappingCollectorConfig | undefined,
	reservedKeyPolicy: ReservedKeyPolicy,
): ResolvedAttributeMapping[] {
	const attributes = config?.attributes;
	if (!Array.isArray(attributes) || attributes.length === 0) {
		throw new Error(`${collector}: attributes must be a non-empty array of mappings`);
	}
	return attributes.map((mapping, index) => {
		const { from, to, type = "string" } = mapping ?? {};
		if (typeof from !== "string" || from === "") {
			throw new Error(`${collector}: attributes[${index}].from must be a non-empty string`);
		}
		if (to !== undefined && (typeof to !== "string" || to === "")) {
			throw new Error(`${collector}: attributes[${index}].to must be a non-empty string`);
		}
		if (!ATTRIBUTE_MAPPING_TYPES.includes(type)) {
			throw new Error(
				`${collector}: attributes[${index}].type must be one of ${ATTRIBUTE_MAPPING_TYPES.join(", ")}, got "${type}"`,
			);
		}
		// Checked on the resolved key, not on `to`: `to` defaults to `from`,
		// so `{ from = "scopes" }` reaches a reserved key without spelling it out.
		const key = to ?? from;
		const reservation = attributeKeyReservation(key);
		if (reservation !== undefined) {
			const refusal = reservedKeyPolicy(index, reservation);
			if (refusal !== undefined) throw new Error(refusal);
		}
		return { from, to: key, type };
	});
}

/**
 * Reads a field: the exact own key when the source has one, else a dot path
 * traversing own properties only. Both sources this serves can carry anything,
 * so inherited members (`constructor`, `toString`, …) must not be reachable
 * through a configured name.
 */
export function readPath(root: Record<string, unknown>, path: string): unknown {
	if (Object.hasOwn(root, path)) return root[path];
	let current: unknown = root;
	for (const segment of path.split(".")) {
		if (typeof current !== "object" || current === null) return undefined;
		if (!Object.hasOwn(current, segment)) return undefined;
		current = (current as Record<string, unknown>)[segment];
	}
	return current;
}

/** Whether `value` is usable as the declared type. Empty strings count as absent. */
export function matchesType(value: unknown, type: AttributeMappingType): boolean {
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

/** Promotes every declared field whose value matches its declared type. */
export function promoteMappings(
	mappings: readonly ResolvedAttributeMapping[],
	source: Record<string, unknown>,
): Attributes {
	const attrs: Attributes = new Map();
	for (const mapping of mappings) {
		const raw = readPath(source, mapping.from);
		if (matchesType(raw, mapping.type)) {
			attrs.set(mapping.to, Array.isArray(raw) ? [...raw] : raw);
		}
	}
	return attrs;
}
