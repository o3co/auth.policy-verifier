// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { createSecretKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { KeyResolver, KeyResolverFactory, Module } from "@o3co/auth.policy-verifier.core";
import { createRemoteJWKSet, importSPKI } from "jose";

interface JwtFactoryInput {
	secret?: string;
	jwksUri?: string;
	publicKey?: string;
	publicKeyPath?: string;
}

/**
 * Shared resolver for RS256/ES256/EdDSA. Accepts JWKS URI, inline PEM, or PEM
 * file path (in that priority). Throws if no key source is configured.
 */
async function resolveAsymmetric(algorithm: string, config: JwtFactoryInput): Promise<KeyResolver> {
	if (config.jwksUri) {
		const key = createRemoteJWKSet(new URL(config.jwksUri));
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

/** Resolves an HS256 symmetric key from `config.secret`. Throws if absent. */
export const HS256KeyResolverFactory: KeyResolverFactory = async (config: JwtFactoryInput) => {
	if (!config.secret) {
		throw new Error("secret is required for HS256");
	}
	const key = createSecretKey(new TextEncoder().encode(config.secret));
	return { key, algorithms: ["HS256"] };
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
