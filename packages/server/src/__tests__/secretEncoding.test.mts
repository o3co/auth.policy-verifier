// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { createHmac } from "node:crypto";
import {
	type AttributeCollectorFactory,
	Registry,
	type ResourceParserFactory,
	type RuleCollectorFactory,
} from "@o3co/auth.policy-verifier.core";
import { type JWTVerifyGetKey, jwtVerify, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import type { KeyResolverFactory } from "#/auth/keyResolver.mjs";
import type { TokenAuthenticatorFactory } from "#/auth/tokenAuthenticator.mjs";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { checkHs256Rotation } from "#/config/hs256Rotation.mjs";
import { checkSecretEncoding, decodeSecret, SECRET_ENCODINGS } from "#/config/secretEncoding.mjs";
import { createApp } from "#/index.mjs";
import { builtinKeyResolversModule } from "#/jwt/builtinKeyResolversModule.mjs";

/** 32 random-looking bytes, written the three ways an issuer may hold them. */
const KEY_BYTES = Buffer.from(
	"a3f1c9d2e47b085566aa19cc3d8e0f7142b6d5e9801c37fa5d2e6b90c4137e88",
	"hex",
);
const AS_HEX = KEY_BYTES.toString("hex");
const AS_BASE64 = KEY_BYTES.toString("base64");

const OTHER_BYTES = Buffer.from("b4".repeat(16) + "7c".repeat(16), "hex");
const OTHER_HEX = OTHER_BYTES.toString("hex");
const OTHER_BASE64 = OTHER_BYTES.toString("base64");

const FUTURE = "2999-01-01T00:00:00Z";

function makeContext() {
	return {
		pathResolver: (s: string) => s,
		config: {} as Record<string, unknown>,
		attributeCollectorRegistry: new Registry<AttributeCollectorFactory>(),
		ruleCollectorRegistry: new Registry<RuleCollectorFactory>(),
		resourceParserRegistry: new Registry<ResourceParserFactory>(),
		keyResolverRegistry: new Registry<KeyResolverFactory>(),
		tokenAuthenticatorRegistry: new Registry<TokenAuthenticatorFactory>(),
	};
}

async function hs256Factory(): Promise<KeyResolverFactory> {
	const context = makeContext();
	await builtinKeyResolversModule.init(context);
	return context.keyResolverRegistry.get("HS256");
}

/** Mints a token whose HMAC key is exactly `keyBytes`, the way an issuer that decoded its secret does. */
async function signWith(keyBytes: Uint8Array, kid?: string): Promise<string> {
	return await new SignJWT({ sub: "u1" })
		.setProtectedHeader(kid === undefined ? { alg: "HS256" } : { alg: "HS256", kid })
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(keyBytes);
}

async function accepts(config: Record<string, unknown>, token: string): Promise<boolean> {
	const resolver = await (await hs256Factory())({ algorithm: "HS256", ...config });
	try {
		await jwtVerify(token, resolver.key as JWTVerifyGetKey, { algorithms: resolver.algorithms });
		return true;
	} catch {
		return false;
	}
}

describe("decodeSecret — the bytes each encoding reads", () => {
	it("reads utf8 as the text's own bytes", () => {
		expect(decodeSecret("héllo", "utf8")).toEqual(Buffer.from("héllo", "utf8"));
	});

	it("reads hex as whole bytes of hex, either case", () => {
		expect(decodeSecret(AS_HEX, "hex")).toEqual(KEY_BYTES);
		expect(decodeSecret(AS_HEX.toUpperCase(), "hex")).toEqual(KEY_BYTES);
	});

	it("refuses hex that is not whole bytes of hex", () => {
		expect(decodeSecret("abc", "hex")).toBeUndefined();
		expect(decodeSecret("zz".repeat(16), "hex")).toBeUndefined();
		expect(decodeSecret("", "hex")).toBeUndefined();
	});

	it("reads padded standard base64", () => {
		expect(decodeSecret(AS_BASE64, "base64")).toEqual(KEY_BYTES);
		expect(decodeSecret("YQ==", "base64")).toEqual(Buffer.from("a"));
	});

	it("refuses base64 outside the padded standard alphabet", () => {
		expect(decodeSecret("YQ", "base64")).toBeUndefined(); // unpadded
		expect(decodeSecret("a-b_cd==", "base64")).toBeUndefined(); // url-safe alphabet
		expect(decodeSecret("not base64!", "base64")).toBeUndefined();
		expect(decodeSecret("", "base64")).toBeUndefined();
	});
});

describe("HS256 secretEncoding — the key the verifier holds", () => {
	it("hex: verifies a token signed with the decoded bytes, and refuses it under the default", async () => {
		const token = await signWith(KEY_BYTES);
		expect(await accepts({ secret: AS_HEX, secretEncoding: "hex" }, token)).toBe(true);
		expect(await accepts({ secret: AS_HEX }, token)).toBe(false);
		expect(await accepts({ secret: AS_HEX, secretEncoding: "utf8" }, token)).toBe(false);
	});

	it("base64: verifies a token signed with the decoded bytes, and refuses it under the default", async () => {
		const token = await signWith(KEY_BYTES);
		expect(await accepts({ secret: AS_BASE64, secretEncoding: "base64" }, token)).toBe(true);
		expect(await accepts({ secret: AS_BASE64 }, token)).toBe(false);
	});

	it("default and explicit utf8 read the text's own bytes, as before", async () => {
		const token = await signWith(new TextEncoder().encode(AS_HEX));
		expect(await accepts({ secret: AS_HEX }, token)).toBe(true);
		expect(await accepts({ secret: AS_HEX, secretEncoding: "utf8" }, token)).toBe(true);
		expect(await accepts({ secret: AS_HEX, secretEncoding: "hex" }, token)).toBe(false);
	});

	it("reads a previous secret with the same encoding as the current one", async () => {
		const config = {
			secret: AS_HEX,
			secretEncoding: "hex",
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: OTHER_HEX, expiresAt: FUTURE }],
		};
		expect(await accepts(config, await signWith(OTHER_BYTES, "v0"))).toBe(true);
		expect(await accepts(config, await signWith(KEY_BYTES, "v1"))).toBe(true);
		expect(await accepts(config, await signWith(new TextEncoder().encode(OTHER_HEX), "v0"))).toBe(
			false,
		);
	});

	it("reads a previous secret as base64 under base64, and finds it without a kid", async () => {
		const config = {
			secret: AS_BASE64,
			secretEncoding: "base64",
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: OTHER_BASE64, expiresAt: FUTURE }],
		};
		expect(await accepts(config, await signWith(OTHER_BYTES))).toBe(true);
	});

	it("keys the HMAC the same as the bytes an issuer decoded (signature equality)", async () => {
		const resolver = await (await hs256Factory())({
			algorithm: "HS256",
			secret: AS_HEX,
			secretEncoding: "hex",
		});
		const key = resolver.key as { export(): Buffer };
		expect(createHmac("sha256", key.export()).update("m").digest("hex")).toBe(
			createHmac("sha256", KEY_BYTES).update("m").digest("hex"),
		);
	});
});

describe("HS256 secretEncoding — refusal at both boundaries", () => {
	const wire = (jwt: Record<string, unknown>) => ({
		oauth: {
			jwt: {
				algorithm: "HS256",
				issuer: "https://issuer.test",
				audience: "https://api.test",
				...jwt,
			},
		},
		attribute: { collectors: [] },
		rule: { collectors: [] },
	});

	function schemaMessages(jwt: Record<string, unknown>): string[] {
		const result = AppConfigSchema.safeParse(wire(jwt));
		return result.success
			? []
			: result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
	}

	async function guardMessage(jwt: Record<string, unknown>): Promise<string | undefined> {
		try {
			await (await hs256Factory())({ algorithm: "HS256", ...jwt });
			return undefined;
		} catch (cause) {
			return (cause as Error).message;
		}
	}

	it("refuses a non-hex value under hex, naming the key", async () => {
		const jwt = { secret: `${"zz".repeat(32)}`, secretEncoding: "hex" };
		expect(schemaMessages(jwt).join("\n")).toMatch(/oauth\.jwt\.secret.*not hex/s);
		expect(await guardMessage(jwt)).toMatch(/oauth\.jwt\.secret.*not hex/s);
	});

	it("refuses invalid base64 under base64, naming the key", async () => {
		const jwt = { secret: "not base64!".repeat(5), secretEncoding: "base64" };
		expect(schemaMessages(jwt).join("\n")).toMatch(/oauth\.jwt\.secret.*not base64/s);
		expect(await guardMessage(jwt)).toMatch(/oauth\.jwt\.secret.*not base64/s);
	});

	it("refuses an undecodable previous secret, naming its path", async () => {
		const jwt = {
			secret: AS_HEX,
			secretEncoding: "hex",
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: "nothex".repeat(11), expiresAt: FUTURE }],
		};
		expect(schemaMessages(jwt).join("\n")).toMatch(/previousSecrets\.0\.secret.*not hex/s);
		expect(await guardMessage(jwt)).toMatch(/previousSecrets\[0\]\.secret.*not hex/s);
	});

	it.each([["HEX"], ["base64url"], [""], [1], [null], [true]])(
		"refuses the unknown encoding %j, naming oauth.jwt.secretEncoding",
		async (value) => {
			const jwt = { secret: AS_HEX, secretEncoding: value };
			expect(schemaMessages(jwt).join("\n")).toMatch(/oauth\.jwt\.secretEncoding/);
			expect(await guardMessage(jwt)).toMatch(/oauth\.jwt\.secretEncoding/);
		},
	);

	it("never echoes the secret in a refusal", async () => {
		const secret = "Zq9-secret-not-hex-Zq9-secret-not-hex";
		const jwt = { secret, secretEncoding: "hex" };
		expect(schemaMessages(jwt).join("\n")).not.toContain(secret);
		expect(await guardMessage(jwt)).not.toContain(secret);
	});

	it("accepts a valid hex config at both boundaries", async () => {
		const jwt = { secret: AS_HEX, secretEncoding: "hex" };
		expect(schemaMessages(jwt)).toEqual([]);
		expect(await guardMessage(jwt)).toBeUndefined();
	});

	it("applies the same default at both boundaries: absent means utf8", async () => {
		const parsed = AppConfigSchema.parse(wire({ secret: AS_HEX }));
		const jwt = parsed.oauth?.jwt as Record<string, unknown>;
		expect(jwt.secretEncoding).toBe("utf8");
		const token = await signWith(new TextEncoder().encode(AS_HEX));
		expect(await accepts(jwt, token)).toBe(true);
		expect(checkHs256Rotation({ secret: AS_HEX })).toMatchObject({
			ok: true,
			secretEncoding: "utf8",
		});
	});

	it("writes a named encoding back into the parsed config", () => {
		const parsed = AppConfigSchema.parse(wire({ secret: AS_HEX, secretEncoding: "hex" }));
		expect(parsed.oauth?.jwt?.secretEncoding).toBe("hex");
	});

	it("reports an invalid encoding once, not again for each previous secret", () => {
		const result = checkHs256Rotation({
			secret: AS_HEX,
			secretEncoding: "latin1",
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: "short", expiresAt: FUTURE }],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues.map((i) => i.path)).toEqual([["secretEncoding"]]);
		}
	});
});

describe("secretEncoding — the allow-list cannot be widened", () => {
	it("is frozen, and mutating it neither succeeds nor widens the check", () => {
		expect(Object.isFrozen(SECRET_ENCODINGS)).toBe(true);
		expect(() => (SECRET_ENCODINGS as unknown as string[]).push("latin1")).toThrow(TypeError);
		expect(checkSecretEncoding("latin1").ok).toBe(false);
	});
});

describe("decodeSecret — a caller that ignores the types", () => {
	it("names the problem when the secret is not a string", () => {
		expect(() => decodeSecret(42 as unknown as string, "hex")).toThrow(
			/decodeSecret: secret must be a string/,
		);
	});
});

describe("createApp — the hand-off from config to key resolver", () => {
	it("verifies a token signed with the hex-decoded key", async () => {
		const config = AppConfigSchema.parse({
			oauth: {
				jwt: {
					secret: AS_HEX,
					secretEncoding: "hex",
					issuer: "https://issuer.test",
					audience: "https://api.test",
				},
			},
			attribute: { collectors: [{ collector: "S" }] },
			rule: { collectors: [{ collector: "R" }] },
			resource: { parser: "P" },
		});
		const app = await createApp({
			pathResolver: (s: string) => s,
			config,
			modules: [
				builtinKeyResolversModule,
				{
					name: "t",
					async init(context) {
						context.attributeCollectorRegistry.register("S", () => ({
							async collect() {
								return new Map();
							},
						}));
						context.ruleCollectorRegistry.register("R", () => ({
							async collect() {
								return [];
							},
						}));
						context.resourceParserRegistry.register("P", () => ({
							parse: (raw: string) => ({ raw, resourceType: raw, resourceId: undefined }),
						}));
					},
				},
			],
		});
		const sign = (key: Uint8Array) =>
			new SignJWT({})
				.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
				.setIssuedAt()
				.setExpirationTime("1h")
				.setIssuer("https://issuer.test")
				.setAudience("https://api.test")
				.sign(key);
		const good = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${await sign(KEY_BYTES)}`)
			.send({ resource: "x", action: "read" });
		const bad = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${await sign(new TextEncoder().encode(AS_HEX))}`)
			.send({ resource: "x", action: "read" });
		expect(good.status).not.toBe(401);
		expect(bad.status).toBe(401);
	});
});

describe("HS256 secretEncoding — the entropy floor is judged on decoded bytes", () => {
	it("passes 64 hex characters under hex (32 bytes)", () => {
		expect(checkHs256Rotation({ secret: AS_HEX, secretEncoding: "hex" }).ok).toBe(true);
	});

	it("refuses 32 hex characters under hex (16 bytes)", () => {
		const result = checkHs256Rotation({ secret: OTHER_HEX.slice(0, 32), secretEncoding: "hex" });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.message).toMatch(/at least 32 bytes.*carries 16/s);
		}
	});

	it("measures base64 on the decoded length", () => {
		const short = Buffer.from(AS_HEX.slice(0, 40), "hex").toString("base64");
		expect(checkHs256Rotation({ secret: AS_BASE64, secretEncoding: "base64" }).ok).toBe(true);
		expect(checkHs256Rotation({ secret: short, secretEncoding: "base64" }).ok).toBe(false);
	});

	it("holds a previous secret to the same decoded floor", () => {
		const result = checkHs256Rotation({
			secret: AS_HEX,
			secretEncoding: "hex",
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: OTHER_HEX.slice(0, 32), expiresAt: FUTURE }],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.path).toEqual(["previousSecrets", 0, "secret"]);
		}
	});

	it("leaves the utf8 measurement exactly as it was", () => {
		// 16 random bytes as 32 hex characters: the smallest reading is 16, refused.
		expect(checkHs256Rotation({ secret: OTHER_HEX.slice(0, 32) }).ok).toBe(false);
		expect(checkHs256Rotation({ secret: OTHER_HEX.slice(0, 32), secretEncoding: "utf8" }).ok).toBe(
			false,
		);
		expect(checkHs256Rotation({ secret: AS_HEX, secretEncoding: "utf8" }).ok).toBe(true);
	});
});

describe("secretEncoding — a config-shape check in every mode and algorithm", () => {
	const base = {
		issuer: "https://issuer.test",
		audience: "https://api.test",
	};
	const wire = (jwt: Record<string, unknown>) => ({
		oauth: { jwt },
		attribute: { collectors: [] },
		rule: { collectors: [] },
	});
	const encodingIssues = (jwt: Record<string, unknown>) => {
		const result = AppConfigSchema.safeParse(wire(jwt));
		return result.success
			? []
			: result.error.issues.filter((i) => i.path.join(".") === "oauth.jwt.secretEncoding");
	};

	it.each([
		["RS256", { ...base, algorithm: "RS256", publicKey: "pem" }],
		["a custom algorithm", { ...base, algorithm: "HS512", secret: AS_HEX }],
		["insecure-decode", { mode: "insecure-decode" }],
	])("refuses an unknown encoding under %s rather than reading it as utf8", (_label, jwt) => {
		expect(encodingIssues({ ...jwt, secretEncoding: "hexx" })).toHaveLength(1);
	});

	it.each([
		["RS256", { ...base, algorithm: "RS256", publicKey: "pem" }],
		["insecure-decode", { mode: "insecure-decode" }],
	])("accepts a named encoding under %s, as the template sets one in every mode", (_label, jwt) => {
		const result = AppConfigSchema.safeParse(wire({ ...jwt, secretEncoding: "utf8" }));
		expect(result.success).toBe(true);
	});

	it("reports an unknown encoding once under HS256 verification", () => {
		const jwt = { ...base, algorithm: "HS256", secret: AS_HEX, secretEncoding: "hexx" };
		expect(encodingIssues(jwt)).toHaveLength(1);
	});
});
