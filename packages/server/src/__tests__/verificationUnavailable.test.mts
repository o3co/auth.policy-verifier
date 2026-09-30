// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * `verification_unavailable` end to end: the built-in authenticator over a
 * real remote key set (jose's `createRemoteJWKSet`, reached on loopback), and
 * a registered authenticator, both through the verify router. A token whose
 * keys cannot be fetched is `503 verification_unavailable`; a key set that
 * answered without the token's `kid` is `401 invalid_token`; either way
 * nothing is allowed.
 */
import { generateKeyPair } from "node:crypto";
import { createServer, type Server } from "node:http";
import { promisify } from "node:util";
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import { AttributePipeline, consoleLogger, RulePipeline } from "@o3co/auth.policy-verifier.core";
import express from "express";
import { exportJWK, type KeyObject, SignJWT } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import type { TokenAuthenticator } from "#/auth/tokenAuthenticator.mjs";
import { createTokenAuthenticator, RS256KeyResolverFactory } from "#/jwt/index.mjs";
import { createVerifyRouter } from "#/routes/verify.mjs";

const generateKeyPairAsync = promisify(generateKeyPair);
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";
const { privateKey, publicKey } = await generateKeyPairAsync("rsa", { modulusLength: 2048 });

const quietLogger = { ...consoleLogger, warn: () => {}, error: () => {}, info: () => {} };

const appWith = (authenticator: TokenAuthenticator) =>
	express().use(
		createVerifyRouter({
			authenticator,
			logger: quietLogger,
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
		}),
	);

const signToken = (kid: string) =>
	new SignJWT({ scope: "read:project" })
		.setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid })
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setSubject("user-1")
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(privateKey as KeyObject);

describe("verification_unavailable over a real remote key set", () => {
	const servers: Server[] = [];
	afterEach(async () => {
		await Promise.all(
			servers.splice(0).map(
				(server) =>
					new Promise<void>((resolve) => {
						server.closeAllConnections();
						server.close(() => resolve());
					}),
			),
		);
	});

	/** A loopback JWKS endpoint serving `keys`, or a port nothing listens on. */
	const jwksAt = async (keys: object[] | "closed"): Promise<string> => {
		const server = createServer((_req, res) => {
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ keys }));
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const { port } = server.address() as { port: number };
		if (keys === "closed") {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		} else {
			servers.push(server);
		}
		return `http://127.0.0.1:${port}/.well-known/jwks.json`;
	};

	const authenticatorFor = async (jwksUri: string, jwksCooldownMs?: number) => {
		const resolver = await RS256KeyResolverFactory({ algorithm: "RS256", jwksUri, jwksCooldownMs });
		return createTokenAuthenticator(
			{
				validate: true,
				key: resolver.key,
				algorithms: resolver.algorithms,
				issuer: ISSUER,
				audience: AUDIENCE,
				tokenType: "at+jwt",
			},
			quietLogger,
		);
	};

	const verify = async (authenticator: TokenAuthenticator, kid: string) =>
		request(appWith(authenticator))
			.post("/verify")
			.set("Authorization", `Bearer ${await signToken(kid)}`)
			.send({ resource: "project", action: "read" });

	it("answers 503 verification_unavailable when the key set cannot be fetched", async () => {
		const res = await verify(await authenticatorFor(await jwksAt("closed")), "k1");

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			decision: "deny",
			code: "verification_unavailable",
			message: "Token verification is unavailable",
		});
	});

	it("answers 401 invalid_token when the fetched key set has no key for the kid", async () => {
		const jwk = { ...(await exportJWK(publicKey)), kid: "other", alg: "RS256", use: "sig" };

		const res = await verify(await authenticatorFor(await jwksAt([jwk])), "k1");

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	// Past the cooldown an unknown kid fetches the set again, and a fetch that
	// fails is the keys being unavailable, not the token being bad.
	it("answers 503 when an unknown kid refetches past the cooldown and the refetch fails", async () => {
		const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
		const jwksUri = await jwksAt([jwk]);
		const authenticator = await authenticatorFor(jwksUri, 0);
		expect((await verify(authenticator, "k1")).status).toBe(200);
		for (const server of servers.splice(0)) {
			server.closeAllConnections();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}

		const res = await verify(authenticator, "k2");

		expect(res.status).toBe(503);
		expect(res.body.code).toBe("verification_unavailable");
	});

	it("allows a token whose key the fetched set carries", async () => {
		const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };

		const res = await verify(await authenticatorFor(await jwksAt([jwk])), "k1");

		expect(res.status).toBe(200);
	});
});

describe("verification_unavailable from a registered authenticator", () => {
	it("answers the code 503, as the route answers it for the built-in one", async () => {
		const authenticator: TokenAuthenticator = {
			authenticate: async () => ({
				ok: false,
				code: "verification_unavailable",
				message: "introspection endpoint unreachable",
			}),
		};

		const res = await request(appWith(authenticator))
			.post("/verify")
			.set("Authorization", "Bearer opaque")
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			decision: "deny",
			code: "verification_unavailable",
			message: "introspection endpoint unreachable",
		});
	});
});
