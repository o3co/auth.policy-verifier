// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The attribute collector that promotes operator-declared fields of the
 * caller-supplied `requestContext` into attributes, refusing at construction a
 * mapping onto any reserved key.
 */

import type {
	AttributeCollector,
	AttributeKeyReservation,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import {
	CORE_ATTRIBUTE_KEY_OWNER,
	readUntrustedRequestContext,
	suggestUnreservedAttributeKey,
} from "@o3co/auth.policy-verifier.core";
import {
	type AttributeMapping,
	type AttributeMappingCollectorConfig,
	type AttributeMappingType,
	parseAttributeMappings,
	promoteMappings,
	type ResolvedAttributeMapping,
} from "./_attributeMapping.mjs";

/** Types a `requestContext` field may be promoted as. */
export type RequestContextAttributeType = AttributeMappingType;

/**
 * One field this collector promotes out of `requestContext`. `to` may not
 * name a reserved key — core's five, plus whatever the packages a composition
 * loaded reserved for themselves. See the class doc comment for why the
 * caller's body may not land on vocabulary a deployment writes.
 */
export type RequestContextAttributeMapping = AttributeMapping;

/** Config entry accepted by `RequestContextAttributeCollector`. */
export type RequestContextAttributeCollectorConfig = AttributeMappingCollectorConfig;

/**
 * Promotes declared fields of `CollectorContext.requestContext` into attributes.
 *
 * Core assumes no shape for `requestContext` and keeps its `ATTR_*` vocabulary
 * to OAuth/OIDC/RBAC standards, so this collector invents no vocabulary either:
 * the operator declares which fields to read and what to call them, and nothing
 * undeclared is promoted. That declaration is the trust boundary —
 * `requestContext` is caller-supplied and unvalidated, so a field the config did
 * not name cannot reach a rule, and one whose value does not match its declared
 * type is dropped rather than passed along.
 *
 * A mapping's `to` may not name a key any package has reserved: core's five —
 * `scopes`, `permissions`, `roles`, `userId`, `clientId` — and whatever other
 * packages reserved before this collector is constructed (cedar's four
 * `request*` keys, once it is imported). The check is a lookup in core's
 * registry at construction; a later reservation is not seen. Those keys are
 * what the engine decides from, written by the deployment, and the request
 * body must not join them: `AttributePipeline` unions array-valued attributes,
 * so `{ from = "groups", to = "scopes" }` would quietly add to the token's
 * scopes; a scalar key written with a different value throws
 * `AttributeConflictError` and denies, and where its owner writes it only
 * sometimes (cedar's `requestResourceId` for an id-less resource) the
 * caller's value stands unopposed. Such a mapping is a configuration error,
 * refused at construction so the deployment fails at boot. Only the attribute
 * key is reserved: `{ from = "scopes", to = "requestedScopes" }` is fine.
 *
 * Configuration, with an example: the package README, RequestContextAttributeCollector.
 */
export class RequestContextAttributeCollector implements AttributeCollector {
	private readonly mappings: ResolvedAttributeMapping[];

	constructor(config: RequestContextAttributeCollectorConfig) {
		// Every reserved destination is refused here — the source is the caller's
		// body. The declaration parsing is shared with the collector that reads
		// verified claims; the policy is this collector's own.
		this.mappings = parseAttributeMappings("RequestContextAttributeCollector", config, refusal);
	}

	async collect(context: CollectorContext): Promise<Attributes> {
		// The unwrap is the acknowledgement `UntrustedRequestContext` asks for:
		// everything below this line is the caller's own data, which is why the
		// mapping list — not the request — decides what becomes an attribute.
		const requestContext = readUntrustedRequestContext(context.requestContext);
		if (requestContext === undefined) return new Map();
		return promoteMappings(this.mappings, requestContext);
	}
}

/**
 * Why this mapping is refused, in the words of whoever owns the key. Core's
 * five get the trust boundary they sit on; another package's keys get its name
 * and its own stated reason, so the operator knows whose docs to read.
 *
 * The suggested rename is drawn from core's registry rather than always
 * `request<Key>`: `request*` is cedar's namespace, and advice landing there
 * would be refused by this same guard.
 */
function refusal(index: number, reservation: AttributeKeyReservation): string {
	const { key, owner, reason } = reservation;
	const head =
		owner === CORE_ATTRIBUTE_KEY_OWNER
			? `RequestContextAttributeCollector: attributes[${index}] maps onto the reserved core attribute "${key}". ` +
				"That key is the engine's own vocabulary, written by the deployment — from the " +
				"signature-verified token for scopes/userId/clientId, from configuration for roles/permissions — " +
				"while requestContext is caller-supplied, and array attributes union across collectors, so this " +
				"mapping would let the request body extend the deployment's value rather than contribute a " +
				"separate attribute. "
			: `RequestContextAttributeCollector: attributes[${index}] maps onto the reserved attribute "${key}", ` +
				`which belongs to ${owner}${reason === undefined ? "" : ` — ${reason}`}. ` +
				"That package writes the key from what the deployment established, while requestContext is " +
				"caller-supplied: where both write it the values collide and every such request is denied, and " +
				"where that package writes nothing for a given request the caller's value stands unopposed as " +
				"the one the deployment was supposed to supply. ";
	return `${head}Promote the field under a key of your own (for example "${suggestUnreservedAttributeKey(key)}").`;
}
