// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
import { ATTR_CLIENT_ID, ATTR_USER_ID } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { PayloadSubjectIdCollector } from "#/collectors/PayloadSubjectIdCollector.mjs";

/**
 * `CollectorContext.signal` is required: a pipeline supplies one per
 * collector, so a hand-built context carries one too. These fixtures are not
 * about cancellation, so it is a signal that never aborts.
 */
const NEVER_CANCELLED = new AbortController().signal;

const makeContext = (subject: SubjectAttributes): CollectorContext => ({
	subject,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
	signal: NEVER_CANCELLED,
});

describe("PayloadSubjectIdCollector", () => {
	const collector = new PayloadSubjectIdCollector();

	it("extracts userId from subject.sub", async () => {
		const attrs = await collector.collect(makeContext({ sub: "u1" }));
		expect(attrs.get(ATTR_USER_ID)).toBe("u1");
	});

	it("extracts clientId from subject.azp", async () => {
		const attrs = await collector.collect(makeContext({ azp: "c1" }));
		expect(attrs.get(ATTR_CLIENT_ID)).toBe("c1");
	});

	it("extracts clientId from subject.client_id", async () => {
		const attrs = await collector.collect(makeContext({ client_id: "c1" }));
		expect(attrs.get(ATTR_CLIENT_ID)).toBe("c1");
	});

	it("reads an RFC 9068 access token, which names its client in client_id and has no azp", async () => {
		// The claim set RFC 9068 §2.2 defines, which includes no `azp` and no `sid`.
		const attrs = await collector.collect(
			makeContext({
				iss: "https://issuer.example",
				sub: "u1",
				aud: "https://api.example",
				client_id: "c1",
				scope: "read:project",
				exp: 1_900_000_000,
				iat: 1_800_000_000,
				jti: "j1",
			}),
		);
		expect(attrs).toEqual(
			new Map([
				[ATTR_USER_ID, "u1"],
				[ATTR_CLIENT_ID, "c1"],
			]),
		);
	});

	it("extracts clientId when client_id and azp name the same client", async () => {
		const attrs = await collector.collect(makeContext({ client_id: "c1", azp: "c1" }));
		expect(attrs.get(ATTR_CLIENT_ID)).toBe("c1");
	});

	it("leaves clientId unset when client_id and azp name different clients", async () => {
		// Neither claim outranks the other, so either value would be a guess.
		const attrs = await collector.collect(makeContext({ sub: "u1", client_id: "c1", azp: "c2" }));
		expect(attrs.has(ATTR_CLIENT_ID)).toBe(false);
		expect(attrs.get(ATTR_USER_ID)).toBe("u1");
	});

	it.each([
		["client_id is not a string", { client_id: 42, azp: "c1" }],
		["client_id is empty", { client_id: "", azp: "c1" }],
		["client_id is null", { client_id: null, azp: "c1" }],
		["azp is not a string", { client_id: "c1", azp: ["c1"] }],
		["azp is empty", { client_id: "c1", azp: "" }],
	])("leaves clientId unset when %s beside a valid claim", async (_label, subject) => {
		const attrs = await collector.collect(makeContext(subject));
		expect(attrs.has(ATTR_CLIENT_ID)).toBe(false);
	});

	it("promotes no claim the subject only inherits", async () => {
		const inherited = Object.create({ sub: "u1", client_id: "c1", azp: "c1" }) as SubjectAttributes;
		const attrs = await collector.collect(makeContext(inherited));
		expect(attrs.size).toBe(0);
	});

	it("does not let an inherited client claim contradict the token's own", async () => {
		const subject = Object.assign(Object.create({ client_id: "c2" }), {
			azp: "c1",
		}) as SubjectAttributes;
		const attrs = await collector.collect(makeContext(subject));
		expect(attrs.get(ATTR_CLIENT_ID)).toBe("c1");
	});

	it("returns empty map when neither sub nor a client claim is present", async () => {
		const attrs = await collector.collect(makeContext({}));
		expect(attrs.size).toBe(0);
	});

	it("promotes neither claim when its value is not a string", async () => {
		// `SubjectAttributes` is a bag of unknowns: the claim vocabulary
		// and its narrowing are this collector's, so a `sub` that is not a string
		// must not become an identity attribute.
		const attrs = await collector.collect(makeContext({ sub: 42, azp: ["c1"], client_id: 7 }));
		expect(attrs.size).toBe(0);
	});

	it("promotes neither claim when its value is an empty string", async () => {
		const attrs = await collector.collect(makeContext({ sub: "", azp: "", client_id: "" }));
		expect(attrs.size).toBe(0);
	});
});
