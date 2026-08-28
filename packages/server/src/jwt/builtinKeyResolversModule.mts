// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { createSecretKey, type KeyObject } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { KeyResolver, KeyResolverFactory, Module } from "@o3co/auth.policy-verifier.core";
import {
	createRemoteJWKSet,
	errors,
	type FlattenedJWSInput,
	flattenedVerify,
	importSPKI,
	type JWSHeaderParameters,
	type JWTVerifyGetKey,
} from "jose";
import { type Hs256RotationConfig, parseHs256Rotation } from "./hs256Rotation.mjs";
import { type JwksFetchConfig, parseJwksUri, resolveJwksFetchBounds } from "./jwks.mjs";

interface JwtFactoryInput extends JwksFetchConfig, Hs256RotationConfig {
	secret?: string;
	jwksUri?: string;
	publicKey?: string;
	publicKeyPath?: string;
}

/**
 * Shared resolver for RS256/ES256/EdDSA. Accepts JWKS URI, inline PEM, or PEM
 * file path (in that priority). Throws if no key source is configured.
 *
 * A JWKS URI must be https, or http on a loopback host — see the trust
 * assumption and the carve-out in `jwt/jwks.mts` (#109). Checked here as well as
 * in `AppConfigSchema`, through the one shared function — see AGENTS.md,
 * "Two-Boundary Config Validation".
 */
async function resolveAsymmetric(algorithm: string, config: JwtFactoryInput): Promise<KeyResolver> {
	if (config.jwksUri) {
		const key = createRemoteJWKSet(parseJwksUri(config.jwksUri), resolveJwksFetchBounds(config));
		return { key, algorithms: [algorithm] };
	}
	if (config.publicKey) {
		const key = await importSPKI(config.publicKey, algorithm);
		return { key, algorithms: [algorithm] };
	}
	if (config.publicKeyPath) {
		const pem = await readFile(config.publicKeyPath, "utf-8");
		const key = await importSPKI(pem, algorithm);
		return { key, algorithms: [algorithm] };
	}
	throw new Error(`jwksUri or publicKey/publicKeyPath is required for ${algorithm}`);
}

/** One HS256 secret as key material, with the moment it stops being one. */
interface Hs256Key {
	kid: string;
	key: KeyObject;
	/** Epoch milliseconds, or `undefined` for the current secret, which does not expire. */
	expiresAtMs?: number;
}

/** Turns a configured secret string into an HMAC key. */
function toSecretKey(secret: string): KeyObject {
	return createSecretKey(new TextEncoder().encode(secret));
}

/**
 * True when `candidate` is the key this token was signed with.
 *
 * The trial runs through jose's own flattened verification rather than a
 * hand-rolled HMAC comparison: `jwtVerify` hands the key resolver the very
 * `{ protected, payload, signature }` triple `flattenedVerify` consumes, so the
 * check is the same code path jose is about to run, with no second opinion
 * about base64url decoding or constant-time comparison living here.
 *
 * `algorithms` is pinned even though `jwtVerify` has already refused anything
 * but HS256 before calling the resolver — this function must not become the one
 * place where a token talks its way into a different algorithm.
 */
async function signedWith(token: FlattenedJWSInput, candidate: KeyObject): Promise<boolean> {
	try {
		await flattenedVerify(token, candidate, { algorithms: ["HS256"] });
		return true;
	} catch {
		return false;
	}
}

/**
 * Builds the `kid`-aware key resolution used once a deployment configures more
 * than a bare secret (#112).
 *
 * Two paths, because a token may or may not name the key it was signed with:
 *
 * - **`kid` present** — direct lookup, and an unrecognised one is refused
 *   outright. This is auth.provider's own model: it stamps the signing `kid`
 *   into every token it mints and resolves by that `kid` alone, never trial-
 *   verifying. Matching that here keeps the cost of a forged header at one map
 *   lookup.
 * - **`kid` absent** — every live secret is tried in turn. RFC 7515 §4.1.4
 *   makes `kid` optional, and an HS256 token really can arrive without one:
 *   there is nothing in a symmetric token that has to identify the key, no JWKS
 *   to look it up in, and any issuer or fixture minting with a bare
 *   `{ alg: "HS256" }` header produces exactly that. Refusing those would make
 *   rotation trade one outage for another, so they cost one signature check per
 *   configured secret instead — which is the whole reason `MAX_PREVIOUS_SECRETS`
 *   caps the list.
 *
 * `expiresAt` is applied on both paths, per request rather than at boot: the
 * overlap window has to close on its own in a long-running verifier, and a
 * retired secret past its window is one that can still mint tokens.
 *
 * A refusal is raised as `JWKSNoMatchingKey`, deliberately: `kid` is
 * attacker-controlled, and `isVerificationUnavailable` judges that class
 * token-side, so a stream of invented `kid`s is answered with warn-level
 * `jwt_token_rejected` lines instead of an error-level channel that drowns the
 * signal a real provider outage would produce (#107).
 */
function createRotatingKeyResolver(keys: Hs256Key[], current: KeyObject): JWTVerifyGetKey {
	const byKid = new Map(keys.map((entry) => [entry.kid, entry]));
	const isLive = (entry: Hs256Key, nowMs: number): boolean =>
		entry.expiresAtMs === undefined || entry.expiresAtMs > nowMs;

	return async (protectedHeader: JWSHeaderParameters, token: FlattenedJWSInput) => {
		const nowMs = Date.now();
		const { kid } = protectedHeader;
		if (kid !== undefined) {
			const entry = byKid.get(kid);
			if (entry === undefined) {
				throw new errors.JWKSNoMatchingKey('no configured HS256 secret matches the token "kid"');
			}
			if (!isLive(entry, nowMs)) {
				throw new errors.JWKSNoMatchingKey(
					'the HS256 secret for the token "kid" is past its configured expiresAt',
				);
			}
			return entry.key;
		}
		for (const entry of keys) {
			if (isLive(entry, nowMs) && (await signedWith(token, entry.key))) {
				return entry.key;
			}
		}
		// Nothing matched. Hand back the current key rather than throwing, so the
		// rejection jose reports is the ordinary JWSSignatureVerificationFailed a
		// wrong secret has always produced — a token signed with a secret this
		// deployment does not hold is not a key-resolution problem.
		return current;
	};
}

/**
 * Resolves HS256 verification key material from `config.secret`, plus the
 * retired secrets a rotation leaves overlapping (#112). Throws if no secret is
 * configured, or if the rotation block is malformed.
 *
 * A config with neither `kid` nor `previousSecrets` — every deployment written
 * before #112, and every one that has never rotated — resolves to the bare
 * secret key it always did, with the token header never consulted. Rotation is
 * opt-in, and opting in is what starts pinning `kid`.
 */
export const HS256KeyResolverFactory: KeyResolverFactory = async (config: JwtFactoryInput) => {
	if (!config.secret) {
		throw new Error("secret is required for HS256");
	}
	// Checked here as well as in `AppConfigSchema`, through the one shared
	// function, as for the JWKS URI above — see AGENTS.md, "Two-Boundary Config
	// Validation".
	const { kid, previousSecrets } = parseHs256Rotation(config);
	const current = toSecretKey(config.secret);
	if (kid === undefined && previousSecrets.length === 0) {
		return { key: current, algorithms: ["HS256"] };
	}
	const keys: Hs256Key[] = [
		// `kid` is guaranteed present here: `parseHs256Rotation` requires it
		// whenever `previousSecrets` is non-empty, and the branch above returned
		// for the case where both are absent.
		{ kid: kid as string, key: current },
		...previousSecrets.map((previous) => ({
			kid: previous.kid,
			key: toSecretKey(previous.secret),
			expiresAtMs: Date.parse(previous.expiresAt),
		})),
	];
	return { key: createRotatingKeyResolver(keys, current), algorithms: ["HS256"] };
};

/** Resolves an RS256 public key from JWKS / PEM string / PEM file. */
export const RS256KeyResolverFactory: KeyResolverFactory = (config: JwtFactoryInput) =>
	resolveAsymmetric("RS256", config);

/** Resolves an ES256 public key from JWKS / PEM string / PEM file. */
export const ES256KeyResolverFactory: KeyResolverFactory = (config: JwtFactoryInput) =>
	resolveAsymmetric("ES256", config);

/** Resolves an EdDSA public key from JWKS / PEM string / PEM file. */
export const EdDSAKeyResolverFactory: KeyResolverFactory = (config: JwtFactoryInput) =>
	resolveAsymmetric("EdDSA", config);

/**
 * `Module` that registers the four built-in JWT key resolver factories
 * (HS256 / RS256 / ES256 / EdDSA) on the `keyResolverRegistry`. Include in
 * `createApp({ modules })` to enable the default algorithms.
 */
export const builtinKeyResolversModule: Module = {
	name: "builtin-key-resolvers",
	async init(context) {
		context.keyResolverRegistry.register("HS256", HS256KeyResolverFactory);
		context.keyResolverRegistry.register("RS256", RS256KeyResolverFactory);
		context.keyResolverRegistry.register("ES256", ES256KeyResolverFactory);
		context.keyResolverRegistry.register("EdDSA", EdDSAKeyResolverFactory);
	},
};
