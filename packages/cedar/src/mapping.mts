// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Turns the merged attributes into one Cedar authorization request: validates
 * the principal, action, resource and context mapping of a collector's config
 * at boot, and builds the request from it per call as a pure function of the
 * attributes.
 *
 * The request's entities are a set keyed by uid, not a list of roles (#282).
 * A role — principal, resource — is a reference to an entity, and what its
 * mapping says of that entity is a contribution to it. Cedar holds one
 * description per entity, and refuses a request that gives one uid two
 * different ones. So when two roles name one entity — a user acting on their
 * own record — their contributions are reconciled here, and how is the
 * deployment's `sharedEntity` (see {@link SharedEntity}): by default the
 * principal's describes it and the resource's may add nothing.
 */

import type { ReadonlyAttributes } from "@o3co/auth.policy-verifier.core";
import { ATTR_USER_ID } from "@o3co/auth.policy-verifier.core";
import type { CedarContext, CedarEntity, CedarEntityUid, CedarValue } from "./cedarJson.mjs";
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

/**
 * How the request's entity is described when the principal and the resource
 * are one entity (#282) — a user acting on their own record. Cedar holds one
 * description per entity, and what either role's mapping contributes to it is
 * read through both `principal` and `resource`.
 *
 * - `"strict"` (**default**): the principal's mapping describes the entity,
 *   and the resource's may repeat what it says but add nothing — an attribute
 *   or parent the principal's mapping does not give. What both declare must
 *   agree, absence included: a name both map, like `dept` for
 *   `principal.dept == resource.dept`, passes only when both sides give it the
 *   same value. Anything else refuses the request (`not_invoked`, logged,
 *   naming what differs), so nothing the resource mapping says of that entity
 *   can reach `principal`. A request passes as one entity when the resource
 *   mapping's own names and parent types are absent on it.
 * - `"merge"`: the deployment states that its resource mapping's sources are
 *   as trusted as its principal mapping's. What both mappings declare — an
 *   attribute name, a parent entity type — must agree, absence included;
 *   what only one declares is added. So on self-access a policy reading
 *   `principal.x` can see an `x` only the resource mapping declares, and
 *   `principal in Group::"g"` a membership only it gives: choose it only where
 *   no caller-supplied attribute feeds the resource mapping.
 *
 * The action is a role too, one no mapping describes: a caller naming the
 * request's own action as the resource may add nothing to it, under either
 * setting — there is no mapping of it to be trusted as.
 */
export type SharedEntity = "strict" | "merge";

const SHARED_ENTITY: readonly SharedEntity[] = ["strict", "merge"];

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
	sharedEntity: SharedEntity;
}

/**
 * One authorization request in Cedar's JSON form, entities inline: what an
 * engine's `isAuthorized` receives. Built per request from the attribute map
 * by {@link buildCedarRequest}; the evaluator, wasm or remote, adds nothing
 * but the policy set it was loaded with.
 */
export interface CedarRequest {
	principal: CedarEntityUid;
	action: CedarEntityUid;
	resource: CedarEntityUid;
	context: CedarContext;
	entities: CedarEntity[];
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
		sharedEntity: sharedEntity(config.sharedEntity),
	};
	// A principal that is an action would be the request's own action whenever
	// its id matched — one entity described as a user and invoked as a verb.
	if (resolved.principalType === resolved.actionType) {
		throw new Error(
			`CedarPolicyRuleCollector: principal.type and action.type must differ, both are ${JSON.stringify(resolved.principalType)}`,
		);
	}
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
 *
 * When the principal and the resource are one entity, an omission is kept a
 * statement: under either `sharedEntity`, a name both mappings declare must be
 * omitted by both or given the same value by both, so a value from one role
 * never answers a read the other role's mapping left to fail. Only `"merge"`
 * lets one role add a name the other does not declare.
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

	const principal: CedarEntityUid = { type: mapping.principalType, id: principalId };
	const resource: CedarEntityUid = { type: resourceType, id: resourceId };

	const action: CedarEntityUid = { type: mapping.actionType, id: actionId };

	return {
		principal,
		action,
		resource,
		context: buildContext(mapping.context, attrs),
		// In authority order: a later role may repeat what an earlier one says of
		// a shared entity, and — under "merge" only — add to it. The action is
		// named by every request and described by no mapping; it takes part only
		// so that no other role can describe it (a caller naming the request's
		// own action as the resource), and has no entry of its own.
		entities: requestEntities(mapping.sharedEntity, [
			contribution("principal", principal, mapping.principal, attrs),
			{ ...contribution("action", action, {}, attrs), described: false },
			contribution("resource", resource, mapping.resource, attrs),
		]),
	};
}

/**
 * What one role's mapping says of the entity it names: the values it found,
 * and — because an omitted attribute is itself a statement (a policy reading
 * it errors, and denies) — every name and parent type it declares.
 */
interface Contribution {
	role: string;
	uid: CedarEntityUid;
	attrs: Record<string, CedarValue>;
	/** Every attribute name the mapping declares, found or omitted. */
	names: ReadonlySet<string>;
	/** Every parent entity type the mapping declares, with the parents found (none, if absent). */
	parents: ReadonlyMap<string, readonly CedarEntityUid[]>;
	/** Whether the role's entity is an entry of the request — false for the action alone. */
	described: boolean;
}

function contribution(
	role: string,
	uid: CedarEntityUid,
	config: EntityMappingConfig,
	attrs: ReadonlyAttributes,
): Contribution {
	return {
		role,
		uid,
		attrs: buildEntityAttrs(config.attributes, attrs),
		names: new Set(Object.keys(config.attributes ?? {})),
		parents: buildParents(config.parents, attrs),
		described: true,
	};
}

/**
 * A request's entities, one per uid (#282) — see the header. `contributions`
 * come in authority order: the first role to name an entity describes it, and
 * a later role naming it is reconciled with that description under the
 * deployment's {@link SharedEntity}. What cannot be reconciled is refused with
 * a {@link CedarInputError} — a logged deny, like any request the attributes
 * cannot supply — never settled by picking one side. A message names roles,
 * the entity type and the attribute or parent type, never a value or an id:
 * those are the request's data. An entity only undescribed roles name (the
 * action, on its own) is no entry.
 */
function requestEntities(
	sharing: SharedEntity,
	contributions: readonly Contribution[],
): CedarEntity[] {
	const held = new Map<string, Held>();
	for (const offered of contributions) {
		const key = uidKey(offered.uid);
		const record = held.get(key);
		if (record === undefined) {
			const fresh: Held = {
				entity: { uid: offered.uid, attrs: {}, parents: [] },
				roles: [offered.role],
				described: offered.described,
				names: new Set(),
				parents: new Map(),
			};
			held.set(key, fresh);
			absorb(fresh, offered);
			continue;
		}
		// An entity no mapping describes — the request's own action — takes no
		// description from anyone, under either setting: "merge" is a judgement
		// between two mappings' sources, and there is no mapping here to weigh.
		const found =
			sharing === "strict" || !record.described
				? strictDifference(record, offered)
				: mergeConflict(record, offered);
		if (found !== undefined) throw new CedarInputError(refusal(record, offered, found));
		record.roles.push(offered.role);
		record.described ||= offered.described;
		absorb(record, offered);
	}
	const entities = [...held.values()]
		.filter(({ described }) => described)
		.map(({ entity }) => entity);
	refuseCycles(entities);
	return entities;
}

/** What a later description does that the one held does not allow. */
interface Difference {
	/** It adds a fact the held description does not state — a refusal `"merge"` would lift. */
	adds: boolean;
	/** The attribute or parent type, named — never its value. */
	what: string;
}

function refusal(held: Held, offered: Contribution, found: Difference): string {
	if (!held.described) {
		return `the ${offered.role} is the request's ${held.roles.join(" and ")} entity, which no mapping describes, and the ${offered.role} mapping would describe it (${found.what})`;
	}
	const shared = `the ${held.roles.join(" and the ")} and the ${offered.role} are one ${offered.uid.type} entity`;
	if (!found.adds) return `${shared}, and their mappings disagree on it (${found.what})`;
	return `${shared}, and the ${offered.role} mapping would say of it what the ${held.roles[0]} mapping does not (${found.what}) — under sharedEntity = "strict" a later role may repeat, not add; set sharedEntity = "merge" only if the ${offered.role} mapping's sources are as trusted as the ${held.roles[0]}'s`;
}

interface Held {
	entity: CedarEntity;
	/** The roles that named it, in authority order. */
	roles: string[];
	described: boolean;
	names: Set<string>;
	parents: Map<string, Set<string>>;
}

/** Adds what a contribution says that the description does not hold yet. */
function absorb(held: Held, offered: Contribution): void {
	for (const name of offered.names) held.names.add(name);
	for (const [name, value] of Object.entries(offered.attrs)) {
		if (!Object.hasOwn(held.entity.attrs, name)) defineOwn(held.entity.attrs, name, value);
	}
	for (const [type, parents] of offered.parents) {
		let keys = held.parents.get(type);
		if (keys === undefined) {
			keys = new Set();
			held.parents.set(type, keys);
		}
		// Keyed, so each membership is looked at once however many there are:
		// this runs inside `verify`, synchronously, where no deadline reaches.
		for (const parent of parents) {
			const parentKey = uidKey(parent);
			if (keys.has(parentKey)) continue;
			keys.add(parentKey);
			held.entity.parents.push(parent);
		}
	}
}

/**
 * `"strict"`: a later description may repeat the one held but add nothing.
 * What both declare must agree; what only it declares must be absent — an
 * attribute it gives, or a parent, would be a fact the earlier role's mapping
 * never stated, readable through that role.
 */
function strictDifference(held: Held, offered: Contribution): Difference | undefined {
	const disagreement = mergeConflict(held, offered);
	if (disagreement !== undefined) return disagreement;
	for (const name of offered.names) {
		if (!held.names.has(name) && Object.hasOwn(offered.attrs, name)) {
			return { adds: true, what: `attribute "${name}"` };
		}
	}
	for (const [type, parents] of offered.parents) {
		if (!held.parents.has(type) && parents.length > 0) {
			return { adds: true, what: `parents of type "${type}"` };
		}
	}
	return undefined;
}

/**
 * What both descriptions declare must agree — a value on one and an omission
 * on the other included, since an omitted attribute is what makes a policy
 * reading it deny. Under `"merge"` that is all: what only one declares is
 * added. Under `"strict"` it is the first test of two.
 */
function mergeConflict(held: Held, offered: Contribution): Difference | undefined {
	for (const name of offered.names) {
		if (!held.names.has(name)) continue;
		const mine = Object.hasOwn(held.entity.attrs, name) ? held.entity.attrs[name] : undefined;
		const theirs = Object.hasOwn(offered.attrs, name) ? offered.attrs[name] : undefined;
		if (!sameCedarValue(mine, theirs)) return { adds: false, what: `attribute "${name}"` };
	}
	for (const [type, parents] of offered.parents) {
		const mine = held.parents.get(type);
		if (mine === undefined) continue;
		if (!sameKeys(mine, new Set(parents.map(uidKey)))) {
			return { adds: false, what: `parents of type "${type}"` };
		}
	}
	return undefined;
}

/**
 * Refuses entities that would be their own ancestors — a parent naming the
 * entity itself, or two entities each other's. Cedar refuses such a request
 * whole, which the rule would log as a failed call; here it is what it is, a
 * request the attributes cannot supply.
 */
function refuseCycles(entities: readonly CedarEntity[]): void {
	const byKey = new Map(entities.map((entity) => [uidKey(entity.uid), entity]));
	const state = new Map<string, "open" | "done">();
	const visit = (key: string, entity: CedarEntity): void => {
		const at = state.get(key);
		if (at === "done") return;
		if (at === "open") {
			throw new CedarInputError(
				"the request's entities form a membership cycle — an entity would be its own ancestor",
			);
		}
		state.set(key, "open");
		for (const parent of entity.parents) {
			const parentKey = uidKey(parent);
			const next = byKey.get(parentKey);
			if (next !== undefined) visit(parentKey, next);
		}
		state.set(key, "done");
	};
	for (const [key, entity] of byKey) visit(key, entity);
}

/** A uid as one string: type and id both, so `User::"a"` and `Group::"a"` stay apart. */
function uidKey(uid: CedarEntityUid): string {
	return JSON.stringify([uid.type, uid.id]);
}

function sameKeys(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
	if (a.size !== b.size) return false;
	for (const key of a) if (!b.has(key)) return false;
	return true;
}

/**
 * Whether two synthesized values — or an omission, `undefined` — are one value
 * **to Cedar**, the test Cedar applies to two entries for one entity. An array
 * is a Cedar set: order and repetition do not count, so `["eng", "staff"]` is
 * `["staff", "eng", "eng"]`. An entity reference is its uid. Strings, booleans
 * and integers are themselves, and a string is never the integer it spells.
 */
function sameCedarValue(a: CedarValue | undefined, b: CedarValue | undefined): boolean {
	if (a === undefined || b === undefined) return a === b;
	return canonical(a) === canonical(b);
}

function canonical(value: CedarValue): string {
	if (Array.isArray(value)) return `[${[...new Set(value.map(canonical))].sort().join(",")}]`;
	// The mapping builds no records (`toCedarValue` refuses objects): an object
	// here is an entity reference, and is its uid.
	if (typeof value === "object" && value !== null) {
		return `entity:${uidKey((value as { __entity: CedarEntityUid }).__entity)}`;
	}
	return JSON.stringify(value);
}

/**
 * Sets `name` as an own property, whatever it is called: `record.__proto__ =
 * value` would set the object's prototype instead, and the attribute would
 * silently not be there.
 */
function defineOwn<T>(record: Record<string, T>, name: string, value: T): void {
	Object.defineProperty(record, name, {
		value,
		enumerable: true,
		writable: true,
		configurable: true,
	});
}

function sharedEntity(value: unknown): SharedEntity {
	if (value === undefined) return "strict";
	if (typeof value !== "string" || !SHARED_ENTITY.includes(value as SharedEntity)) {
		throw new Error(
			`CedarPolicyRuleCollector: sharedEntity must be one of ${SHARED_ENTITY.join(", ")}, got ${typeof value === "string" ? JSON.stringify(value) : describe(value)}`,
		);
	}
	return value as SharedEntity;
}

/**
 * Converts one attribute value to a Cedar value. `undefined` means "cannot be
 * represented": `null` (Cedar has no null, and its JSON formats fail the whole
 * request on one — see `CedarValue`), non-integer numbers (Cedar `long` is
 * integral), functions, objects, arrays with an unrepresentable element.
 * Callers omit such values — see `buildCedarRequest` for why omission is the
 * safe direction for attributes.
 *
 * Objects are refused on purpose, although `CedarValue` can carry a record: in
 * Cedar's JSON form an object is also where the `__entity` and `__extn`
 * escapes live, so an attribute that arrived as an object — a caller-supplied
 * `requestContext` field promoted by a collector — could name an entity
 * reference the deployment never mapped, and `principal in Group::"admins"`
 * would then be decided by the request body. Entity references are built by
 * the mapping alone, from the `{ attribute, entityType }` form and a string.
 */
function toCedarValue(value: unknown): CedarValue | undefined {
	if (typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") return Number.isSafeInteger(value) ? value : undefined;
	if (Array.isArray(value)) {
		const out: CedarValue[] = [];
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
): Record<string, CedarValue> {
	const out: Record<string, CedarValue> = {};
	if (mappings === undefined) return out;
	for (const [cedarName, mapping] of Object.entries(mappings)) {
		if (typeof mapping === "string") {
			const value = toCedarValue(attrs.get(mapping));
			if (value !== undefined) defineOwn(out, cedarName, value);
			continue;
		}
		const raw = attrs.get(mapping.attribute);
		if (typeof raw === "string" && raw.length > 0) {
			defineOwn(out, cedarName, { __entity: { type: mapping.entityType, id: raw } });
		}
	}
	return out;
}

/** Each declared parent entity type, with the parents found for it — none, when absent. */
function buildParents(
	mappings: Record<string, string> | undefined,
	attrs: ReadonlyAttributes,
): Map<string, CedarEntityUid[]> {
	const byType = new Map<string, CedarEntityUid[]>();
	if (mappings === undefined) return byType;
	for (const [entityType, attrKey] of Object.entries(mappings)) {
		const parents: CedarEntityUid[] = [];
		byType.set(entityType, parents);
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
	return byType;
}

function buildContext(mappings: Record<string, string>, attrs: ReadonlyAttributes): CedarContext {
	const context: CedarContext = {};
	for (const [cedarKey, attrKey] of Object.entries(mappings)) {
		const value = toCedarValue(attrs.get(attrKey));
		if (value !== undefined) defineOwn(context, cedarKey, value);
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
				defineOwn(out, cedarName, mapping);
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
				defineOwn(out, cedarName, { attribute: entry.attribute, entityType: entry.entityType });
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
		defineOwn(out, key, entry);
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
