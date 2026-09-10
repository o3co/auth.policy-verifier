// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

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
 * Promotes declared claims of the verified subject into attributes (#219).
 *
 * The builtins read three claims — `scope`, `sub`, `azp` — and an external
 * IdP puts what a rule needs elsewhere: Clerk's org role under `o.rol`,
 * Auth0's roles under a namespaced `https://example.com/roles`, Okta's groups
 * under `groups`. Until now every one of those meant a bespoke collector,
 * even for the common case of "read this claim, check its type, write it
 * under this key". This is the same declaration `RequestContextAttributeCollector`
 * takes, pointed at `CollectorContext.subject` instead of the caller's body:
 *
 * ```hocon
 * { collector = "PayloadClaimAttributeCollector"
 *   attributes = [
 *     { from = "o.rol", to = "roles", type = "string[]" }
 *     { from = "https://example.com/roles", to = "roles", type = "string[]" }
 *     { from = "tid", to = "tenantId" }
 *   ] }
 * ```
 *
 * ## Core's vocabulary is a valid destination here
 *
 * `RequestContextAttributeCollector` refuses to write `scopes`, `permissions`,
 * `roles`, `userId` and `clientId`, because its source is the request body
 * and those keys are what the engine decides from. This collector's source is
 * the signature-verified token — the same trust `PayloadScopeCollector` writes
 * `scopes` from — so a verified claim may land on them: `permissions` from
 * Auth0's `permissions`, `roles` from Clerk's `o.rol`, `scopes` from Okta's
 * `scp`. Two collectors writing one list key **union** it; that is the
 * deployment composing two issuer-derived sources, and it says so in config.
 *
 * Keys another package reserved — cedar's `request*` — stay refused: those
 * are derived from the parsed request, not from the subject, and a claim
 * landing on one would be a second writer with a different meaning.
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
		"That package derives the key from the request, not from the subject, so a verified claim " +
		"landing on it would be a second writer with a different meaning. " +
		`Promote the claim under a key of your own (for example "${suggestUnreservedAttributeKey(key)}").`
	);
}
