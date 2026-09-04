// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	AttributeCollector,
	AttributeKeyReservation,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import {
	attributeKeyReservation,
	CORE_ATTRIBUTE_KEY_OWNER,
	readUntrustedRequestContext,
	suggestUnreservedAttributeKey,
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
	/**
	 * Attribute key to write. Defaults to `from`.
	 *
	 * May not name a reserved key — core's five, plus whatever the packages a
	 * composition loaded reserved for themselves. See the class doc comment for
	 * why the caller's body may not land on vocabulary a deployment writes.
	 */
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
 * ## Reserved vocabulary is not a valid destination
 *
 * A mapping's `to` may not name a key any package has reserved. Core reserves
 * five — `scopes`, `permissions`, `roles`, `userId`, `clientId` — and every
 * package that owns attribute vocabulary reserves its own at module load:
 * `packages/cedar` reserves `requestAction`, `requestResourceType`,
 * `requestResourceId` and `requestResourceRaw`. The check is a lookup in core's
 * registry, not a list this collector or core keeps by hand, so a package core
 * cannot see is covered by importing it — which a composition naming that
 * package's collectors has already done.
 *
 * Those keys are what the engine decides from, and under the default server
 * `scopes` / `userId` / `clientId` are read out of the signature-verified
 * token; `requestContext` is the request body, which anyone holding a valid
 * token fills in as they like. The two carry different trust and must not share
 * a bucket.
 *
 * The reason it is refused outright rather than left to the operator is what
 * `AttributePipeline` does with two collectors writing one key: array-valued
 * entries **union**. So `{ from = "groups", to = "scopes" }` does not replace
 * the token's scopes and lose an argument with `PayloadScopeCollector` — it
 * quietly *adds to* them, and the request that arrives with
 * `context.groups = ["admin:write"]` is authorized for a scope its token never
 * carried. Nothing in the decision, the logs or the metrics distinguishes that
 * from an issuer that granted it.
 *
 * A scalar key is not safe either, in two different ways. Two writers that
 * disagree throw `AttributeConflictError`, which denies — fail-closed, but an
 * unannounced outage rather than a refusal. And where the owning collector
 * writes its key only *sometimes*, there is no second writer at all: cedar's
 * `RequestFactsCollector` omits `requestResourceId` for an id-less resource
 * such as `"document"`, so `{ from = "rid", to = "requestResourceId" }` would
 * land unopposed and the Cedar resource entity would be built out of the
 * caller's own request body.
 *
 * This is reachable only through operator configuration, which is why it is a
 * configuration error rather than a vulnerability. It is refused at
 * construction — boot, not first request — so a deployment that wrote it never
 * serves a decision. Every other destination keeps working: the *field* may be
 * called anything (`{ from = "scopes", to = "requestedScopes" }` is fine), only
 * the attribute key is reserved.
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
			// Checked on the resolved key, not on `to`: `to` defaults to `from`,
			// so `{ from = "scopes" }` reaches the reserved key without ever
			// spelling it out. See the class doc comment for why this is refused.
			const key = to ?? from;
			const reservation = attributeKeyReservation(key);
			if (reservation !== undefined) {
				throw new Error(refusal(index, reservation));
			}
			return { from, to: key, type };
		});
	}

	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		// The unwrap is the acknowledgement `UntrustedRequestContext` asks for:
		// everything below this line is the caller's own data, which is why the
		// mapping list — not the request — decides what becomes an attribute.
		const requestContext = readUntrustedRequestContext(context.requestContext);
		if (requestContext === undefined) return attrs;

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
 * Why this mapping is refused, in the words of whoever owns the key.
 *
 * Core's five get the account of the trust boundary they sit on. Another
 * package's keys get its name and its own stated reason instead: asserting they
 * are "the core vocabulary" would be false, and the operator's next move is to
 * go read that package's docs, so the message says which one.
 *
 * The suggested rename is drawn from core's registry rather than spelled
 * `request<Key>` unconditionally, because `request*` is a real package's
 * namespace (cedar's) and advice that lands there would be refused by this same
 * guard.
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
