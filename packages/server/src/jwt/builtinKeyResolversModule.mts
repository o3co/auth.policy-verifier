// Copyright 2026 1o1 Co. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

export const HS256KeyResolverFactory: KeyResolverFactory = async (config: JwtFactoryInput) => {
	if (!config.secret) {
		throw new Error("secret is required for HS256");
	}
	const key = createSecretKey(new TextEncoder().encode(config.secret));
	return { key, algorithms: ["HS256"] };
};

export const RS256KeyResolverFactory: KeyResolverFactory = (config: JwtFactoryInput) =>
	resolveAsymmetric("RS256", config);

export const ES256KeyResolverFactory: KeyResolverFactory = (config: JwtFactoryInput) =>
	resolveAsymmetric("ES256", config);

export const EdDSAKeyResolverFactory: KeyResolverFactory = (config: JwtFactoryInput) =>
	resolveAsymmetric("EdDSA", config);

export const builtinKeyResolversModule: Module = {
	name: "builtin-key-resolvers",
	async init(context) {
		context.keyResolverRegistry.register("HS256", HS256KeyResolverFactory);
		context.keyResolverRegistry.register("RS256", RS256KeyResolverFactory);
		context.keyResolverRegistry.register("ES256", ES256KeyResolverFactory);
		context.keyResolverRegistry.register("EdDSA", EdDSAKeyResolverFactory);
	},
};
