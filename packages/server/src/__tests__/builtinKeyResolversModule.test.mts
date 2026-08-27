// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { generateKeyPair } from "node:crypto";
import { createServer, type Server } from "node:http";
import {
	createServer as createSocketServer,
	type Socket,
	type Server as SocketServer,
} from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { promisify } from "node:util";
import {
	type AttributeCollectorFactory,
	type KeyResolverFactory,
	Registry,
	type ResourceParserFactory,
	type RuleCollectorFactory,
} from "@o3co/auth.policy-verifier.core";
import {
	exportJWK,
	exportSPKI,
	type JWTVerifyGetKey,
	jwtVerify,
	type KeyObject,
	type RemoteJWKSet,
	SignJWT,
} from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { MAX_PREVIOUS_SECRETS } from "#/config/defaults.mjs";
import { builtinKeyResolversModule } from "#/jwt/builtinKeyResolversModule.mjs";

const generateKeyPairAsync = promisify(generateKeyPair);

function makeContext() {
	return {
		pathResolver: (s: string) => s,
		config: {} as Record<string, unknown>,
		attributeCollectorRegistry: new Registry<AttributeCollectorFactory>(),
		ruleCollectorRegistry: new Registry<RuleCollectorFactory>(),
		resourceParserRegistry: new Registry<ResourceParserFactory>(),
		keyResolverRegistry: new Registry<KeyResolverFactory>(),
	};
}

describe("builtinKeyResolversModule", () => {
	it("registers HS256, RS256, ES256, EdDSA factories", async () => {
		const context = makeContext();
		await builtinKeyResolversModule.init(context);

		expect(context.keyResolverRegistry.has("HS256")).toBe(true);
		expect(context.keyResolverRegistry.has("RS256")).toBe(true);
		expect(context.keyResolverRegistry.has("ES256")).toBe(true);
		expect(context.keyResolverRegistry.has("EdDSA")).toBe(true);
	});

	it("HS256 factory builds a resolver from secret", async () => {
		const context = makeContext();
		await builtinKeyResolversModule.init(context);

		const factory = context.keyResolverRegistry.get("HS256");
		const resolver = await factory({ algorithm: "HS256", secret: "test-secret", validate: true });

		expect(resolver.algorithms).toEqual(["HS256"]);
		expect(resolver.key).toBeDefined();
	});

	it("HS256 factory throws when secret is missing", async () => {
		const context = makeContext();
		await builtinKeyResolversModule.init(context);

		const factory = context.keyResolverRegistry.get("HS256");
		await expect(factory({ algorithm: "HS256", validate: true })).rejects.toThrow(
			"secret is required for HS256",
		);
	});

	it("RS256 factory builds a resolver from publicKey PEM", async () => {
		const context = makeContext();
		await builtinKeyResolversModule.init(context);

		const { publicKey } = await generateKeyPairAsync("rsa", { modulusLength: 2048 });
		const pem = await exportSPKI(publicKey as unknown as CryptoKey);

		const factory = context.keyResolverRegistry.get("RS256");
		const resolver = await factory({ algorithm: "RS256", publicKey: pem, validate: true });

		expect(resolver.algorithms).toEqual(["RS256"]);
		expect(resolver.key).toBeDefined();
	});

	it("RS256 factory builds a resolver from jwksUri (returns function key)", async () => {
		const context = makeContext();
		await builtinKeyResolversModule.init(context);

		const factory = context.keyResolverRegistry.get("RS256");
		const resolver = await factory({
			algorithm: "RS256",
			jwksUri: "https://example.com/.well-known/jwks.json",
			validate: true,
		});

		expect(resolver.algorithms).toEqual(["RS256"]);
		expect(typeof resolver.key).toBe("function");
	});

	it("EdDSA factory builds a resolver from publicKey PEM", async () => {
		const context = makeContext();
		await builtinKeyResolversModule.init(context);

		const { publicKey } = await generateKeyPairAsync("ed25519");
		const pem = await exportSPKI(publicKey as unknown as CryptoKey);

		const factory = context.keyResolverRegistry.get("EdDSA");
		const resolver = await factory({ algorithm: "EdDSA", publicKey: pem, validate: true });

		expect(resolver.algorithms).toEqual(["EdDSA"]);
		expect(resolver.key).toBeDefined();
	});

	it("asymmetric factories throw when no key source is provided", async () => {
		const context = makeContext();
		await builtinKeyResolversModule.init(context);

		const factory = context.keyResolverRegistry.get("RS256");
		await expect(factory({ algorithm: "RS256", validate: true })).rejects.toThrow(
			/jwksUri or publicKey/,
		);
	});
});

/** Resolves the RS256 factory from a freshly initialized registry. */
async function rs256Factory(): Promise<KeyResolverFactory> {
	const context = makeContext();
	await builtinKeyResolversModule.init(context);
	return context.keyResolverRegistry.get("RS256");
}

describe("builtinKeyResolversModule — JWKS transport security (#109)", () => {
	// AppConfigSchema rejects these at config-parse time; the factory re-checks
	// because createApp also accepts hand-built configs that never went through
	// the schema — the same division of labor as assertVerifyRouterJwtConfig.
	it("refuses a plaintext jwksUri on a routable host", async () => {
		const factory = await rs256Factory();
		await expect(
			factory({ algorithm: "RS256", jwksUri: "http://auth-provider:3000/.well-known/jwks.json" }),
		).rejects.toThrow(/https/);
	});

	it("refuses a jwksUri that is not an absolute URL", async () => {
		const factory = await rs256Factory();
		await expect(
			factory({ algorithm: "RS256", jwksUri: "auth-provider/.well-known/jwks.json" }),
		).rejects.toThrow(/absolute URL/);
	});

	it.each([
		"http://localhost:3000/.well-known/jwks.json",
		"http://127.0.0.1:3000/.well-known/jwks.json",
		"http://[::1]:3000/.well-known/jwks.json",
	])("accepts plaintext %s — the loopback carve-out", async (jwksUri) => {
		const factory = await rs256Factory();
		const resolver = await factory({ algorithm: "RS256", jwksUri });
		expect(typeof resolver.key).toBe("function");
	});
});

describe("builtinKeyResolversModule — JWKS fetch bounds (#109)", () => {
	const servers: (Server | SocketServer)[] = [];
	const sockets: Socket[] = [];

	afterEach(async () => {
		// `close` waits for open connections, and the hung-fetch case leaves one
		// behind on purpose — drop them by hand or the hook times out.
		for (const socket of sockets.splice(0)) {
			socket.destroy();
		}
		await Promise.all(
			servers.splice(0).map((server) => {
				if ("closeAllConnections" in server) {
					server.closeAllConnections();
				}
				return new Promise<void>((resolve) => {
					server.close(() => resolve());
				});
			}),
		);
	});

	/** Starts a server on an ephemeral loopback port and returns its origin. */
	async function listen(server: Server | SocketServer): Promise<string> {
		servers.push(server);
		await new Promise<void>((resolve) => {
			server.listen(0, "127.0.0.1", resolve);
		});
		const address = server.address();
		if (address === null || typeof address === "string") {
			throw new Error("expected a TCP address");
		}
		return `http://127.0.0.1:${address.port}`;
	}

	it("aborts a JWKS fetch that hangs past the configured timeout", async () => {
		// A socket that is accepted and never answered: without a timeout the
		// verification would wait forever on the decision hot path.
		const origin = await listen(
			createSocketServer((socket) => {
				sockets.push(socket);
			}),
		);
		const factory = await rs256Factory();
		const resolver = await factory({
			algorithm: "RS256",
			jwksUri: `${origin}/.well-known/jwks.json`,
			jwksTimeoutMs: 50,
		});

		const started = Date.now();
		await expect((resolver.key as RemoteJWKSet)({ alg: "RS256", kid: "any" })).rejects.toThrow(
			/timed out/,
		);
		expect(Date.now() - started).toBeLessThan(2000);
	});

	it("coerces a string bound before handing it to jose", async () => {
		// A hand-built config assembled from process.env carries strings; jose
		// ignores a non-number and would silently fall back to its own 5s default.
		const origin = await listen(
			createSocketServer((socket) => {
				sockets.push(socket);
			}),
		);
		const factory = await rs256Factory();
		const resolver = await factory({
			algorithm: "RS256",
			jwksUri: `${origin}/.well-known/jwks.json`,
			jwksTimeoutMs: "50",
		});

		const started = Date.now();
		await expect((resolver.key as RemoteJWKSet)({ alg: "RS256", kid: "any" })).rejects.toThrow(
			/timed out/,
		);
		expect(Date.now() - started).toBeLessThan(2000);
	});

	it("refuses a bound it cannot make sense of, naming the config key", async () => {
		const factory = await rs256Factory();
		await expect(
			factory({
				algorithm: "RS256",
				jwksUri: "https://auth-provider.test/.well-known/jwks.json",
				jwksCooldownMs: "often",
			}),
		).rejects.toThrow(/oauth\.jwt\.jwksCooldownMs must be a non-negative integer/);
	});

	it("hands the configured cooldown and cache age to the remote key set", async () => {
		const { publicKey } = await generateKeyPairAsync("rsa", { modulusLength: 2048 });
		const jwk = {
			...(await exportJWK(publicKey as unknown as CryptoKey)),
			kid: "k1",
			alg: "RS256",
		};
		const origin = await listen(
			createServer((_req, res) => {
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ keys: [jwk] }));
			}),
		);
		const jwksUri = `${origin}/.well-known/jwks.json`;
		const factory = await rs256Factory();

		const tuned = (
			await factory({ algorithm: "RS256", jwksUri, jwksCooldownMs: 0, jwksCacheMaxAgeMs: 1 })
		).key as RemoteJWKSet;
		await tuned({ alg: "RS256", kid: "k1" });
		await sleep(10);
		expect(tuned.coolingDown).toBe(false);
		expect(tuned.fresh).toBe(false);

		// Same endpoint, defaults — proves the assertions above read the
		// operator's values and not a constant jose would have applied anyway.
		const defaulted = (await factory({ algorithm: "RS256", jwksUri })).key as RemoteJWKSet;
		await defaulted({ alg: "RS256", kid: "k1" });
		expect(defaulted.coolingDown).toBe(true);
		expect(defaulted.fresh).toBe(true);
	});
});

describe("HS256KeyResolverFactory — secret rotation (#112)", () => {
	/** 64 hex characters — 32 decoded bytes, the floor auth.provider#282 set. */
	const CURRENT = "11".repeat(32);
	const PREVIOUS = "22".repeat(32);
	const STRANGER = "33".repeat(32);

	const FUTURE = "2999-01-01T00:00:00Z";
	const PAST = "2000-01-01T00:00:00Z";

	/** Resolves the HS256 factory from a freshly initialized registry. */
	async function hs256Factory(): Promise<KeyResolverFactory> {
		const context = makeContext();
		await builtinKeyResolversModule.init(context);
		return context.keyResolverRegistry.get("HS256");
	}

	/** Mints a token the way auth.provider does — with a `kid`, or deliberately without. */
	async function sign(secret: string, kid?: string): Promise<string> {
		const header = kid === undefined ? { alg: "HS256" } : { alg: "HS256", kid };
		return await new SignJWT({ sub: "u1" })
			.setProtectedHeader(header)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(new TextEncoder().encode(secret));
	}

	/** Runs a token down the resolver exactly as `createTokenAuthenticator` does. */
	async function verify(
		resolver: { key: unknown; algorithms: string[] },
		token: string,
	): Promise<void> {
		await jwtVerify(token, resolver.key as JWTVerifyGetKey, { algorithms: resolver.algorithms });
	}

	const rotated = {
		algorithm: "HS256",
		secret: CURRENT,
		kid: "v1",
		previousSecrets: [{ kid: "v0", secret: PREVIOUS, expiresAt: FUTURE }],
	};

	it("keeps a single-secret config on a static key — the shape that never rotated", async () => {
		// The umbrella E2E and every pre-#112 deployment configure `secret` alone.
		// They must keep verifying tokens whatever `kid` the issuer stamps, so the
		// resolver hands back the bare key and no header lookup happens at all.
		const resolver = await (await hs256Factory())({ algorithm: "HS256", secret: CURRENT });
		expect(typeof resolver.key).not.toBe("function");
		await expect(verify(resolver, await sign(CURRENT, "v0"))).resolves.toBeUndefined();
		await expect(verify(resolver, await sign(CURRENT))).resolves.toBeUndefined();
	});

	it("accepts a token signed by the current secret, by kid", async () => {
		const resolver = await (await hs256Factory())(rotated);
		await expect(verify(resolver, await sign(CURRENT, "v1"))).resolves.toBeUndefined();
	});

	it("accepts a token signed by a retired secret, by kid — the overlap window", async () => {
		const resolver = await (await hs256Factory())(rotated);
		await expect(verify(resolver, await sign(PREVIOUS, "v0"))).resolves.toBeUndefined();
	});

	it("refuses a kid it was never configured with", async () => {
		const resolver = await (await hs256Factory())(rotated);
		await expect(verify(resolver, await sign(STRANGER, "v9"))).rejects.toMatchObject({
			code: "ERR_JWKS_NO_MATCHING_KEY",
		});
	});

	it("refuses a retired secret past its expiresAt", async () => {
		const resolver = await (await hs256Factory())({
			...rotated,
			previousSecrets: [{ kid: "v0", secret: PREVIOUS, expiresAt: PAST }],
		});
		await expect(verify(resolver, await sign(PREVIOUS, "v0"))).rejects.toMatchObject({
			code: "ERR_JWKS_NO_MATCHING_KEY",
		});
		await expect(verify(resolver, await sign(CURRENT, "v1"))).resolves.toBeUndefined();
	});

	describe("tokens that carry no kid at all", () => {
		it("falls back to trying every configured secret", async () => {
			const resolver = await (await hs256Factory())(rotated);
			await expect(verify(resolver, await sign(CURRENT))).resolves.toBeUndefined();
			await expect(verify(resolver, await sign(PREVIOUS))).resolves.toBeUndefined();
		});

		it("still refuses a secret it does not hold", async () => {
			const resolver = await (await hs256Factory())(rotated);
			await expect(verify(resolver, await sign(STRANGER))).rejects.toMatchObject({
				code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
			});
		});

		it("does not try a secret whose overlap window has closed", async () => {
			const resolver = await (await hs256Factory())({
				...rotated,
				previousSecrets: [{ kid: "v0", secret: PREVIOUS, expiresAt: PAST }],
			});
			await expect(verify(resolver, await sign(PREVIOUS))).rejects.toMatchObject({
				code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
			});
		});

		it("bounds the work at one signature check per configured secret", async () => {
			// The reason the list is capped: a token with no kid costs one HMAC per
			// live secret, and an unbounded list makes that an attacker's dial.
			const previousSecrets = Array.from({ length: MAX_PREVIOUS_SECRETS }, (_, i) => ({
				kid: `v${i}`,
				secret: `${i}${i}`.repeat(32),
				expiresAt: FUTURE,
			}));
			const resolver = await (await hs256Factory())({
				algorithm: "HS256",
				secret: CURRENT,
				kid: "current",
				previousSecrets,
			});
			const last = previousSecrets[previousSecrets.length - 1];
			if (last === undefined) throw new Error("expected a capped list to be non-empty");
			await expect(verify(resolver, await sign(last.secret))).resolves.toBeUndefined();
		});
	});

	it("pins a configured kid even without rotation — a mismatch is not waved through", async () => {
		const resolver = await (await hs256Factory())({
			algorithm: "HS256",
			secret: CURRENT,
			kid: "v1",
		});
		await expect(verify(resolver, await sign(CURRENT, "v1"))).resolves.toBeUndefined();
		await expect(verify(resolver, await sign(CURRENT, "v0"))).rejects.toMatchObject({
			code: "ERR_JWKS_NO_MATCHING_KEY",
		});
	});

	it.each([
		[
			"a previous secret with no kid for the current one",
			{ algorithm: "HS256", secret: CURRENT, previousSecrets: rotated.previousSecrets },
			/^oauth\.jwt\.kid is required/,
		],
		[
			"more previous secrets than the cap",
			{
				algorithm: "HS256",
				secret: CURRENT,
				kid: "current",
				previousSecrets: Array.from({ length: MAX_PREVIOUS_SECRETS + 1 }, (_, i) => ({
					kid: `v${i}`,
					secret: PREVIOUS,
					expiresAt: FUTURE,
				})),
			},
			/^oauth\.jwt\.previousSecrets accepts at most/,
		],
		[
			"a duplicated kid",
			{
				algorithm: "HS256",
				secret: CURRENT,
				kid: "v0",
				previousSecrets: [{ kid: "v0", secret: PREVIOUS, expiresAt: FUTURE }],
			},
			/duplicate/i,
		],
		[
			"a malformed expiresAt",
			{
				algorithm: "HS256",
				secret: CURRENT,
				kid: "v1",
				previousSecrets: [{ kid: "v0", secret: PREVIOUS, expiresAt: "soon" }],
			},
			/^oauth\.jwt\.previousSecrets\[0\]\.expiresAt is not a valid timestamp/,
		],
	])("refuses %s at construction", async (_label, config, message) => {
		// AppConfigSchema rejects these at config-parse time; the factory re-checks
		// because createApp also accepts hand-built configs that never went through
		// the schema — the same division of labor as the JWKS transport check.
		await expect((await hs256Factory())(config)).rejects.toThrow(message);
	});

	it("builds one secret key per configured kid", async () => {
		const resolver = await (await hs256Factory())(rotated);
		const key = resolver.key as JWTVerifyGetKey;
		const resolved = (await key(
			{ alg: "HS256", kid: "v0" },
			{
				payload: "",
				signature: "",
			},
		)) as KeyObject;
		expect(resolved.type).toBe("secret");
	});
});
