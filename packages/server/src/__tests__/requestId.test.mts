// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Request correlation for the decision endpoints (#200).
 *
 * `x-request-id` was read and handed to collectors, and #111 put it on the
 * `decision` line — but never on `verify_internal_error`, and never back on the
 * response. So a 500 could not be matched to the enforcing service's own log,
 * which is the one join an operator needs when the verifier is the thing
 * answering 500 at 3 a.m.
 *
 * Now the id the caller sent is on every failure line and echoed on every
 * response the router writes. Two things are refused on purpose:
 *
 * - **Minting one.** An id the server made up and logged, but never returned,
 *   correlates with nothing the caller has. No id sent, no id anywhere.
 * - **Carrying one it cannot vouch for.** The header is the caller's text, and
 *   it now reaches a response header and three log streams. Only a bounded
 *   token of a conservative charset is accepted; anything else is treated as
 *   absent — not echoed, not logged, not forwarded to collectors — rather
 *   than trimmed or escaped into something the caller did not send.
 */
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import {
	type AttributeCollector,
	AttributePipeline,
	type Attributes,
	type EventLogger,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { acceptRequestId, MAX_REQUEST_ID_LENGTH, REQUEST_ID_HEADER } from "#/http/requestId.mjs";
import { HS256KeyResolverFactory } from "#/jwt/index.mjs";
import { createVerifyRouter } from "#/routes/verify.mjs";

/** 64 hex characters — 32 decoded bytes, the entropy floor #114 enforces. */
const JWT_SECRET = "11".repeat(32);
const hs256Key = await HS256KeyResolverFactory({ secret: JWT_SECRET });
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

interface CapturedEvent {
	level: "info" | "warn" | "error";
	obj: Record<string, unknown>;
	msg: string;
}

function captureEvents(): { events: CapturedEvent[]; logger: EventLogger } {
	const events: CapturedEvent[] = [];
	const push = (level: CapturedEvent["level"]) => (obj: Record<string, unknown>, msg?: string) => {
		events.push({ level, obj, msg: msg ?? "" });
	};
	return { events, logger: { info: push("info"), warn: push("warn"), error: push("error") } };
}

const named = (events: CapturedEvent[], msg: string) => events.filter((e) => e.msg === msg);

async function signToken(): Promise<string> {
	return new SignJWT({ sub: "user-1", scope: "read:project" })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setExpirationTime("1h")
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.sign(hs256Key.key as import("node:crypto").KeyObject);
}

/** Fails on `explode`, stalls on `stall`, and records the headers it was handed on every call. */
function recordingCollector(): { collector: AttributeCollector; headers: unknown[] } {
	const headers: unknown[] = [];
	return {
		headers,
		collector: {
			collect: (context): Promise<Attributes> => {
				headers.push(context.headers);
				if (context.action === "explode") return Promise.reject(new Error("store is down"));
				if (context.action === "stall") return new Promise<Attributes>(() => {});
				return Promise.resolve(new Map());
			},
		},
	};
}

function createTestApp() {
	const { events, logger } = captureEvents();
	const recording = recordingCollector();
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: {
				validate: true,
				key: hs256Key.key,
				algorithms: hs256Key.algorithms,
				issuer: ISSUER,
				audience: AUDIENCE,
				tokenType: "at+jwt",
			},
			logger,
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([new PayloadScopeCollector(), recording.collector], {
				collectorTimeoutMs: 30,
			}),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			maxBodyBytes: 256,
		}),
	);
	return { app, events, headers: recording.headers };
}

describe("acceptRequestId (#200)", () => {
	it.each([
		["a UUID", "3f2c5a9e-6d1b-4c1f-9a7e-2b8d4c6e1f00"],
		["a ULID", "01J8ZQ4X9V6M3K2N7P5R8T1W0Y"],
		["the id protobuf.interceptors mints", "20260917123456_0123456789abcdef"],
		["a W3C traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"],
		["base64", "dGhlIHJlcXVlc3QgaWQ+Lw=="],
		["a Kong correlation id", "3f2c5a9e-6d1b-4c1f-9a7e-2b8d4c6e1f00#42"],
		["one character", "7"],
		["exactly the ceiling", "a".repeat(MAX_REQUEST_ID_LENGTH)],
	])("accepts %s", (_what, id) => {
		expect(acceptRequestId(id)).toBe(id);
	});

	it.each([
		["nothing", undefined],
		["an empty value — the proxy that stamps the header with nothing in it", ""],
		["one character over the ceiling", "a".repeat(MAX_REQUEST_ID_LENGTH + 1)],
		["a line break — a forged second log line", "req-1\ninjected=true"],
		["a carriage return", "req-1\rX-Injected: 1"],
		["a space", "req 1"],
		["a tab", "req\t1"],
		["a quote", 'req"1'],
		["a comma — two headers folded into one", "req-1, req-2"],
		["a semicolon", "req-1;evil"],
		["a percent-encoding", "req%0a1"],
		["non-ASCII", "réq-1"],
		["angle brackets", "<script>"],
	])("refuses %s", (_what, id) => {
		expect(acceptRequestId(id)).toBeUndefined();
	});
});

describe("x-request-id on the decision endpoints (#200)", () => {
	const ID = "3f2c5a9e-6d1b-4c1f-9a7e-2b8d4c6e1f00";

	it.each([
		["an allow", "/verify", { resource: "project", action: "read" }, true, 200],
		["a deny", "/verify", { resource: "secret", action: "read" }, true, 403],
		["a malformed body, refused before the token is read", "/verify", [], false, 400],
		["a missing token", "/verify", { resource: "project", action: "read" }, false, 401],
		["a collector fault", "/verify", { resource: "project", action: "explode" }, true, 500],
		[
			"a batch",
			"/verify/batch",
			{ decisions: [{ resource: "project", action: "read" }] },
			true,
			200,
		],
	])("echoes the caller's id on %s", async (_what, endpoint, body, authenticated, status) => {
		const { app } = createTestApp();
		const pending = request(app).post(endpoint).set(REQUEST_ID_HEADER, ID);
		if (authenticated) pending.set("Authorization", `Bearer ${await signToken()}`);

		const res = await pending.send(body as object);

		expect(res.status).toBe(status);
		expect(res.headers[REQUEST_ID_HEADER]).toBe(ID);
	});

	it("echoes it on a refusal the body parser answers, before either route runs", async () => {
		const { app } = createTestApp();

		const res = await request(app)
			.post("/verify")
			.set(REQUEST_ID_HEADER, ID)
			.set("Content-Type", "application/json")
			.send(JSON.stringify({ resource: "x".repeat(512), action: "read" }));

		expect(res.status).toBe(413);
		expect(res.headers[REQUEST_ID_HEADER]).toBe(ID);
	});

	it("carries it on verify_internal_error, on both routes", async () => {
		const { app, events } = createTestApp();
		const token = await signToken();

		await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set(REQUEST_ID_HEADER, ID)
			.send({ resource: "project", action: "explode" });
		await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.set(REQUEST_ID_HEADER, ID)
			.send({ decisions: [{ resource: "project", action: "explode" }] });

		const failures = named(events, "verify_internal_error");
		expect(failures.map((e) => [e.obj.endpoint, e.obj.requestId])).toEqual([
			["/verify", ID],
			["/verify/batch", ID],
		]);
	});

	it("carries it on verify_internal_error from the terminal handler", async () => {
		const { events, logger } = captureEvents();
		const app = express();
		// Something in front of the router set the stream's encoding: the body
		// parser refuses it with a failure the envelope does not map.
		app.use((req, _res, next) => {
			req.setEncoding("utf8");
			next();
		});
		app.use(
			createVerifyRouter({
				jwt: { validate: false, allowInsecureDecode: true },
				logger,
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([]),
				rulePipeline: new RulePipeline([]),
			}),
		);

		const res = await request(app)
			.post("/verify")
			.set(REQUEST_ID_HEADER, ID)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(500);
		expect(res.headers[REQUEST_ID_HEADER]).toBe(ID);
		expect(named(events, "verify_internal_error")[0].obj).toMatchObject({ requestId: ID });
	});

	it("carries the same id on the deny line and the decision line, and forwards it to collectors", async () => {
		const { app, events, headers } = createTestApp();

		await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${await signToken()}`)
			.set(REQUEST_ID_HEADER, ID)
			.send({ resource: "project", action: "stall" });

		expect(named(events, "collector_timeout")[0].obj.requestId).toBe(ID);
		expect(named(events, "decision")[0].obj.requestId).toBe(ID);
		expect(headers[0]).toEqual({ [REQUEST_ID_HEADER]: ID });
	});

	it("mints nothing when the caller sent none: no header, and no id on any line", async () => {
		const { app, events } = createTestApp();

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${await signToken()}`)
			.send({ resource: "project", action: "explode" });

		expect(res.status).toBe(500);
		expect(res.headers).not.toHaveProperty(REQUEST_ID_HEADER);
		for (const event of events) expect(event.obj).not.toHaveProperty("requestId");
	});

	it.each([
		["over the length ceiling", "r".repeat(MAX_REQUEST_ID_LENGTH + 1)],
		["carrying a quote and a brace", 'req-1"}{"sub":"admin'],
		["carrying spaces", "req 1 injected"],
	])("treats an id %s as absent: not echoed, not logged, not forwarded", async (_what, id) => {
		const { app, events, headers } = createTestApp();
		const token = await signToken();

		const failed = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set(REQUEST_ID_HEADER, id)
			.send({ resource: "project", action: "explode" });
		const decided = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set(REQUEST_ID_HEADER, id)
			.send({ resource: "project", action: "read" });

		for (const res of [failed, decided]) {
			expect(res.headers).not.toHaveProperty(REQUEST_ID_HEADER);
		}
		expect(events.length).toBeGreaterThan(0);
		for (const event of events) {
			expect(event.obj).not.toHaveProperty("requestId");
			expect(JSON.stringify(event.obj)).not.toContain(id);
		}
		expect(headers.every((h) => h === undefined)).toBe(true);
	});
});
