// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CedarValueJson, Context, Entities, EntityUid } from "@cedar-policy/cedar-wasm/nodejs";
import type { ReadonlyAttributes } from "@o3co/auth.policy-verifier.core";
import { ATTR_USER_ID } from "@o3co/auth.policy-verifier.core";
import {
	ATTR_REQUEST_ACTION,
	ATTR_REQUEST_RESOURCE_ID,
	ATTR_REQUEST_RESOURCE_TYPE,
} from "./keys.mjs";

/**
 * Raised when the merged attributes cannot be shaped into a Cedar request —
 * a required input is missing, or a value is present but malformed. The rule
 * catches it and denies: an input the mapping cannot vouch for must never
 * become an authorization the deployment did not write.
 */
export class CedarInputError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "CedarInputError";
	}
}

/**
 * One synthesized entity attribute: either a plain value copied from an
 * attribute, or an entity reference built from one (`resource.owner ==
 * principal` needs `owner` to be an entity, not a string).
 */
export type AttributeMapping = string | { attribute: string; entityType: string };

/** Declarative config for one synthesized entity (principal or resource). */
export interface EntityMappingConfig {
	attributes?: Record<string, AttributeMapping>;
	parents?: Record<string, string>;
}

/** Validated mapping the collector resolves once at boot. */
export interface ResolvedMapping {
	principalType: string;
	principalIdAttribute: string;
	principal: EntityMappingConfig;
	actionType: string;
	actionIdAttribute: string;
	resourceTypeAttribute: string;
	resourceIdAttribute: string;
	resourceIdWhenAbsent: string;
	resource: EntityMappingConfig;
	context: Record<string, string>;
}

/** The request shape `statefulIsAuthorized` accepts, minus the preparsed id. */
export interface CedarRequest {
	principal: EntityUid;
	action: EntityUid;
	resource: EntityUid;
	context: Context;
	entities: Entities;
}

/**
 * Validates the mapping section of a `CedarPolicyRuleCollector` config entry
 * and resolves defaults. Runs once at boot, inside the collector factory, so a
 * shape mistake refuses to start rather than denying every request at runtime.
 */
export function resolveMapping(config: Record<string, unknown>): ResolvedMapping {
	const principal = section(config, "principal");
	const action = section(config, "action");
	const resource = section(config, "resource");
	const context = config.context;

	const resolved: ResolvedMapping = {
		principalType: optionalString(principal, "principal.type") ?? "User",
		principalIdAttribute: optionalString(principal, "principal.idAttribute") ?? ATTR_USER_ID,
		principal: entityMapping(principal, "principal"),
		actionType: optionalString(action, "action.type") ?? "Action",
		actionIdAttribute: optionalString(action, "action.idAttribute") ?? ATTR_REQUEST_ACTION,
		resourceTypeAttribute:
			optionalString(resource, "resource.typeAttribute") ?? ATTR_REQUEST_RESOURCE_TYPE,
		resourceIdAttribute:
			optionalString(resource, "resource.idAttribute") ?? ATTR_REQUEST_RESOURCE_ID,
		resourceIdWhenAbsent: optionalString(resource, "resource.idWhenAbsent") ?? "",
		resource: entityMapping(resource, "resource"),
		context: stringRecord(context, "context"),
	};
	return resolved;
}

/**
 * Builds the Cedar authorization request from the merged attributes.
 *
 * Pure: a deterministic function of `(mapping, attrs)`, no I/O, nothing read
 * outside its arguments — it runs inside `Rule.verify` and is bound by the
 * same contract. Throws {@link CedarInputError} when the attributes cannot
 * supply the request; the caller turns that into a deny.
 *
 * Two deliberate asymmetries in how malformed input is treated:
 *
 * - A mapped **attribute** whose value is absent or unmappable is *omitted*
 *   from the synthesized entity. That is fail-closed on its own: any policy
 *   that reads the missing attribute raises a Cedar evaluation error, and the
 *   rule denies on evaluation errors regardless of the abstain knob.
 * - A mapped **parent** whose value is present but malformed *throws*. Parent
 *   omission is not an error to Cedar — membership is simply absent — so a
 *   typo'd `groups` attribute would silently un-member the principal, and a
 *   `forbid (principal in Group::"banned")` policy would silently stop
 *   forbidding. That is the one place omission fails open, so it is the one
 *   place malformed input refuses instead. An *absent* parents attribute stays
 *   legitimate (a principal in no groups).
 */
export function buildCedarRequest(
	mapping: ResolvedMapping,
	attrs: ReadonlyAttributes,
): CedarRequest {
	const principalId = requiredString(attrs, mapping.principalIdAttribute, "principal id");
	const actionId = requiredString(attrs, mapping.actionIdAttribute, "action");
	const resourceType = requiredString(attrs, mapping.resourceTypeAttribute, "resource type");
	const resourceId =
		optionalAttrString(attrs, mapping.resourceIdAttribute, "resource id") ??
		mapping.resourceIdWhenAbsent;

	const principal: EntityUid = { type: mapping.principalType, id: principalId };
	const resource: EntityUid = { type: resourceType, id: resourceId };

	return {
		principal,
		action: { type: mapping.actionType, id: actionId },
		resource,
		context: buildContext(mapping.context, attrs),
		entities: [
			{
				uid: principal,
				attrs: buildEntityAttrs(mapping.principal.attributes, attrs),
				parents: buildParents(mapping.principal.parents, attrs),
			},
			{
				uid: resource,
				attrs: buildEntityAttrs(mapping.resource.attributes, attrs),
				parents: buildParents(mapping.resource.parents, attrs),
			},
		],
	};
}

/**
 * Converts one attribute value to a Cedar value. `undefined` means "cannot be
 * represented": non-integer numbers (Cedar `long` is integral), functions,
 * objects, arrays with an unrepresentable element. Callers omit such values —
 * see `buildCedarRequest` for why omission is the safe direction for
 * attributes.
 */
function toCedarValue(value: unknown): CedarValueJson | undefined {
	if (typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") return Number.isSafeInteger(value) ? value : undefined;
	if (Array.isArray(value)) {
		const out: CedarValueJson[] = [];
		for (const item of value) {
			const converted = toCedarValue(item);
			if (converted === undefined) return undefined;
			out.push(converted);
		}
		return out;
	}
	return undefined;
}

function buildEntityAttrs(
	mappings: Record<string, AttributeMapping> | undefined,
	attrs: ReadonlyAttributes,
): Record<string, CedarValueJson> {
	const out: Record<string, CedarValueJson> = {};
	if (mappings === undefined) return out;
	for (const [cedarName, mapping] of Object.entries(mappings)) {
		if (typeof mapping === "string") {
			const value = toCedarValue(attrs.get(mapping));
			if (value !== undefined) out[cedarName] = value;
			continue;
		}
		const raw = attrs.get(mapping.attribute);
		if (typeof raw === "string" && raw.length > 0) {
			out[cedarName] = { __entity: { type: mapping.entityType, id: raw } };
		}
	}
	return out;
}

function buildParents(
	mappings: Record<string, string> | undefined,
	attrs: ReadonlyAttributes,
): EntityUid[] {
	const parents: EntityUid[] = [];
	if (mappings === undefined) return parents;
	for (const [entityType, attrKey] of Object.entries(mappings)) {
		const raw = attrs.get(attrKey);
		if (raw === undefined) continue; // no memberships is a legitimate state
		const ids = typeof raw === "string" ? [raw] : raw;
		if (!Array.isArray(ids) || !ids.every((id): id is string => typeof id === "string")) {
			throw new CedarInputError(
				`parents attribute "${attrKey}" must be a string or string[], got ${describe(raw)}`,
			);
		}
		for (const id of ids) {
			parents.push({ type: entityType, id });
		}
	}
	return parents;
}

function buildContext(mappings: Record<string, string>, attrs: ReadonlyAttributes): Context {
	const context: Context = {};
	for (const [cedarKey, attrKey] of Object.entries(mappings)) {
		const value = toCedarValue(attrs.get(attrKey));
		if (value !== undefined) context[cedarKey] = value;
	}
	return context;
}

// --- boot-time config shape helpers -----------------------------------------

function section(config: Record<string, unknown>, key: string): Record<string, unknown> {
	const value = config[key];
	if (value === undefined) return {};
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error(
			`CedarPolicyRuleCollector: ${key} must be a config object, got ${describe(value)}`,
		);
	}
	return value as Record<string, unknown>;
}

function optionalString(section: Record<string, unknown>, path: string): string | undefined {
	const key = path.split(".").pop() as string;
	const value = section[key];
	if (value === undefined) return undefined;
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(
			`CedarPolicyRuleCollector: ${path} must be a non-empty string, got ${describe(value)}`,
		);
	}
	return value;
}

function entityMapping(section: Record<string, unknown>, path: string): EntityMappingConfig {
	const attributes = section.attributes;
	const parents = section.parents;
	const resolved: EntityMappingConfig = {};
	if (attributes !== undefined) {
		if (typeof attributes !== "object" || attributes === null || Array.isArray(attributes)) {
			throw new Error(
				`CedarPolicyRuleCollector: ${path}.attributes must be a config object, got ${describe(attributes)}`,
			);
		}
		const out: Record<string, AttributeMapping> = {};
		for (const [cedarName, mapping] of Object.entries(attributes)) {
			if (typeof mapping === "string" && mapping.length > 0) {
				out[cedarName] = mapping;
				continue;
			}
			if (
				typeof mapping === "object" &&
				mapping !== null &&
				!Array.isArray(mapping) &&
				typeof (mapping as Record<string, unknown>).attribute === "string" &&
				typeof (mapping as Record<string, unknown>).entityType === "string"
			) {
				const entry = mapping as { attribute: string; entityType: string };
				out[cedarName] = { attribute: entry.attribute, entityType: entry.entityType };
				continue;
			}
			throw new Error(
				`CedarPolicyRuleCollector: ${path}.attributes.${cedarName} must be an attribute key or { attribute, entityType }, got ${describe(mapping)}`,
			);
		}
		resolved.attributes = out;
	}
	if (parents !== undefined) {
		resolved.parents = stringRecord(parents, `${path}.parents`);
	}
	return resolved;
}

function stringRecord(value: unknown, path: string): Record<string, string> {
	if (value === undefined) return {};
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error(
			`CedarPolicyRuleCollector: ${path} must be a config object, got ${describe(value)}`,
		);
	}
	const out: Record<string, string> = {};
	for (const [key, entry] of Object.entries(value)) {
		if (typeof entry !== "string" || entry.length === 0) {
			throw new Error(
				`CedarPolicyRuleCollector: ${path}.${key} must be a non-empty attribute key, got ${describe(entry)}`,
			);
		}
		out[key] = entry;
	}
	return out;
}

function requiredString(attrs: ReadonlyAttributes, key: string, role: string): string {
	const value = attrs.get(key);
	if (typeof value !== "string" || value.length === 0) {
		throw new CedarInputError(
			`${role} attribute "${key}" must be a non-empty string, got ${describe(value)}`,
		);
	}
	return value;
}

function optionalAttrString(
	attrs: ReadonlyAttributes,
	key: string,
	role: string,
): string | undefined {
	const value = attrs.get(key);
	if (value === undefined) return undefined;
	if (typeof value !== "string") {
		throw new CedarInputError(
			`${role} attribute "${key}" must be a string, got ${describe(value)}`,
		);
	}
	return value;
}

function describe(value: unknown): string {
	if (value === null) return "null";
	if (Array.isArray(value)) return "array";
	return typeof value;
}
