// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The attribute collector that promotes operator-declared claims of the
 * verified subject into attributes, refusing at construction a mapping onto a
 * key another package reserved.
 */

import type {
	AttributeCollector,
	AttributeKeyReservation,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import {
	CORE_ATTRIBUTE_KEY_OWNER,
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

/** One claim this collector promotes out of the verified subject bag. */
export type PayloadClaimAttributeMapping = AttributeMapping;
/** Types a claim may be promoted as. */
export type PayloadClaimAttributeType = AttributeMappingType;
/** Config entry accepted by `PayloadClaimAttributeCollector`. */
export type PayloadClaimAttributeCollectorConfig = AttributeMappingCollectorConfig;

/**
 * Promotes declared claims of the verified subject into attributes. The
 * builtins read `scope`, `sub` and `azp`; an external IdP puts what a rule
 * needs elsewhere — Clerk's org role under `o.rol`, Auth0's roles under a
 * namespaced `https://example.com/roles`, Okta's groups under `groups`. This
 * is the declaration `RequestContextAttributeCollector` takes, pointed at
 * `CollectorContext.subject` instead of the caller's body.
 *
 * The source is the subject the configured authenticator accepted — under the
 * built-in one, a signature-verified token unless `oauth.jwt.mode` is
 * `"insecure-decode"` — not the caller's `requestContext`, so a mapping may land
 * on core's keys (`scopes`, `permissions`, `roles`, `userId`, `clientId`).
 * Keys another package reserved stay refused: that package writes them with a
 * collector of its own — cedar's `request*` from the parsed request, this
 * package's `delegationRange` from the claim `DelegationRangeCollector`
 * narrows — and a claim landing on one would be a second writer with a
 * different meaning.
 *
 * Two cautions the trust argument depends on. Map only claims the IdP
 * populates from its own registration or admin data, never from user-editable
 * profile metadata (Clerk's `unsafe_metadata`, Auth0's `user_metadata`) — a
 * mapping from those hands the end user their own roles. And two collectors
 * writing one list key union it, but a scalar key written by two collectors
 * with different values throws `AttributeConflictError` and denies every
 * request: do not map onto `userId` / `clientId` while
 * `PayloadSubjectIdCollector` writes them.
 *
 * Configuration, with an example: the package README, PayloadClaimAttributeCollector.
 */
export class PayloadClaimAttributeCollector implements AttributeCollector {
	private readonly mappings: ResolvedAttributeMapping[];

	constructor(config: PayloadClaimAttributeCollectorConfig) {
		this.mappings = parseAttributeMappings(
			"PayloadClaimAttributeCollector",
			config,
			(index, reservation) =>
				reservation.owner === CORE_ATTRIBUTE_KEY_OWNER ? undefined : refusal(index, reservation),
		);
	}

	async collect(context: CollectorContext): Promise<Attributes> {
		// The subject bag is what the authenticator verified; nothing here reads
		// `requestContext`, so a caller cannot steer a mapping with the body.
		return promoteMappings(this.mappings, context.subject as Record<string, unknown>);
	}
}

/** Why a mapping onto another package's key is refused, naming that package. */
function refusal(index: number, reservation: AttributeKeyReservation): string {
	const { key, owner, reason } = reservation;
	return (
		`PayloadClaimAttributeCollector: attributes[${index}] maps onto the reserved attribute "${key}", ` +
		`which belongs to ${owner}${reason === undefined ? "" : ` — ${reason}`}. ` +
		"That package writes the key with a collector of its own, so a verified claim landing on it " +
		"would be a second writer with a different meaning. " +
		`Promote the claim under a key of your own (for example "${suggestUnreservedAttributeKey(key)}").`
	);
}
