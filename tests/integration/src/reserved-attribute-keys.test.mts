// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Cross-package reservation, exercised the way a deployment reaches it: through
 * `createApp` with the real modules and a config an operator could write.
 *
 * The guard lives in `packages/builtins`, the vocabulary it protects lives in
 * `packages/cedar`, and the registry both consult lives in `packages/core` —
 * no two of which depend on each other in that direction. This suite is the
 * only place all three are on one dependency graph, which is also exactly the
 * situation a deployment is in.
 */

import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
import {
	ATTR_REQUEST_RESOURCE_ID,
	CEDAR_ATTRIBUTE_KEY_OWNER,
	CEDAR_ATTRIBUTE_KEYS,
	cedarPolicyModule,
} from "@o3co/auth.policy-verifier.cedar";
import type { AttributeCollector, Attributes, Module } from "@o3co/auth.policy-verifier.core";
import {
	ATTR_SCOPES,
	createConsoleLogger,
	RESERVED_ATTRIBUTE_KEYS,
	readUntrustedRequestContext,
} from "@o3co/auth.policy-verifier.core";
import {
	AppConfigSchema,
	builtinKeyResolversModule,
	createApp,
} from "@o3co/auth.policy-verifier.server";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";

/** 64 hex characters — 32 decoded bytes, the entropy floor the server enforces. */
const JWT_SECRET = "11".repeat(32);
const secretKey = new TextEncoder().encode(JWT_SECRET);
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

/** Silent: these cases boot deliberately broken configs and deny on purpose. */
const logger = createConsoleLogger({}, { level: "silent" });

/**
 * One resource the caller may read, and one it may not — named as Cedar
 * entities, which is the whole point: the entity id comes from an attribute,
 * and which collector wrote that attribute is the security question.
 */
const POLICIES = `
permit(principal, action == Action::"read", resource == Document::"public");
permit(principal, action == Action::"read", resource == Document::"someone-elses-doc");
`;

async function signToken(): Promise<string> {
	return new SignJWT({ sub: "user-1", scope: "read:Document" })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setExpirationTime("1h")
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.sign(secretKey);
}

/** The deployment cedar's README describes, with the attribute collectors varied. */
function configWith(attributeCollectors: Record<string, unknown>[]) {
	return AppConfigSchema.parse({
		oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
		attribute: { collectors: attributeCollectors },
		rule: { collectors: [{ collector: "CedarPolicyRuleCollector", policies: POLICIES }] },
		resource: { parser: "DotNotationResourceParser" },
	});
}

const BASE_COLLECTORS = [
	{ collector: "PayloadSubjectIdCollector" },
	{ collector: "RequestFactsCollector" },
];

function boot(attributeCollectors: Record<string, unknown>[], extra: Module[] = []) {
	return createApp({
		pathResolver: (specifier: string) => specifier,
		config: configWith(attributeCollectors),
		modules: [builtinCollectorsModule, cedarPolicyModule, builtinKeyResolversModule, ...extra],
		logger,
	});
}

describe("a package's attribute vocabulary is reserved across package boundaries", () => {
	it("has cedar's keys in core's registry once the module is importable", () => {
		// Importing this package is all a composition does to be able to name
		// `RequestFactsCollector` in config; nothing was constructed yet.
		for (const key of CEDAR_ATTRIBUTE_KEYS) {
			expect(RESERVED_ATTRIBUTE_KEYS.has(key)).toBe(true);
		}
	});

	it.each(CEDAR_ATTRIBUTE_KEYS)(
		"refuses at boot a requestContext mapping onto cedar's %s",
		async (key) => {
			await expect(
				boot([
					...BASE_COLLECTORS,
					{
						collector: "RequestContextAttributeCollector",
						attributes: [{ from: "rid", to: key }],
					},
				]),
			).rejects.toThrow(new RegExp(`"${key}".*${CEDAR_ATTRIBUTE_KEY_OWNER}`, "s"));
		},
	);

	it("still refuses core's own five, and calls them core's", async () => {
		await expect(
			boot([
				...BASE_COLLECTORS,
				{
					collector: "RequestContextAttributeCollector",
					attributes: [{ from: "groups", to: ATTR_SCOPES, type: "string[]" }],
				},
			]),
		).rejects.toThrow(/reserved core attribute "scopes"/);
	});

	it("boots the same deployment when the mapping targets a key of the operator's own", async () => {
		await expect(
			boot([
				...BASE_COLLECTORS,
				{
					collector: "RequestContextAttributeCollector",
					attributes: [{ from: "rid", to: "callerSuppliedResourceId" }],
				},
			]),
		).resolves.toBeDefined();
	});
});

describe("the id-less resource is why the key has to be reserved", () => {
	/*
	 * `RequestFactsCollector` writes `requestResourceId` only when the parsed
	 * resource carried one. For `"Document"` it writes nothing, so a
	 * caller-supplied value would meet no competing writer — no
	 * `AttributeConflictError`, no deny, just the caller's own string arriving
	 * where the deployment's belongs. For `"Document:public"` the two writers
	 * collide instead and the request is denied, which is fail-closed but is an
	 * unannounced denial rather than a refusal.
	 */

	it("refuses the mapping that would decide over the caller's value", async () => {
		await expect(
			boot([
				...BASE_COLLECTORS,
				{
					collector: "RequestContextAttributeCollector",
					attributes: [{ from: "rid", to: ATTR_REQUEST_RESOURCE_ID }],
				},
			]),
		).rejects.toThrow(/requestResourceId/);
	});

	it("denies the id-less request, whose entity id the caller cannot supply", async () => {
		const app = await boot([
			...BASE_COLLECTORS,
			{
				collector: "RequestContextAttributeCollector",
				attributes: [{ from: "rid", to: "callerSuppliedResourceId" }],
			},
		]);
		const token = await signToken();

		const denied = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "Document", action: "read", context: { rid: "someone-elses-doc" } });

		// The policy permitting Document::"someone-elses-doc" exists and matches
		// nothing: the resource entity was built from the parsed request, which
		// carried no id, not from `context.rid`.
		expect(denied.status).toBe(403);
		expect(denied.body.decision).toBe("deny");

		// And the deployment is otherwise live — the permit for a resource the
		// request itself names still allows.
		const allowed = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "Document:public", action: "read", context: { rid: "someone-elses-doc" } });

		expect(allowed.status).toBe(200);
		expect(allowed.body.decision).toBe("allow");
	});

	it("decides over the caller's value once something does write that key", async () => {
		// The escalation itself, reproduced through a hand-written collector —
		// the one shape the framework cannot guard (docs/extending.md leaves a
		// project-side collector's destination keys to its author). It is here to
		// show that the refused config was not a style objection: whoever writes
		// `requestResourceId` chooses the Cedar entity the decision is about.
		const callerChosenId: AttributeCollector = {
			async collect(context) {
				const rid = readUntrustedRequestContext(context.requestContext)?.rid;
				const attrs: Attributes = new Map();
				if (typeof rid === "string" && rid !== "") attrs.set(ATTR_REQUEST_RESOURCE_ID, rid);
				return attrs;
			},
		};
		const unguardedModule: Module = {
			name: "unguarded-caller-chosen-id",
			async init(context) {
				context.attributeCollectorRegistry.register(
					"CallerChosenResourceIdCollector",
					() => callerChosenId,
				);
			},
		};

		const app = await boot(
			[...BASE_COLLECTORS, { collector: "CallerChosenResourceIdCollector" }],
			[unguardedModule],
		);
		const token = await signToken();

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "Document", action: "read", context: { rid: "someone-elses-doc" } });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});
});
