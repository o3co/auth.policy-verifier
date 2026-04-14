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
import { createRemoteJWKSet, importSPKI, type JWTVerifyGetKey } from "jose";

export interface JwtKeyConfig {
	algorithm: "HS256" | "RS256" | "ES256" | "EdDSA";
	secret?: string;
	jwksUri?: string;
	publicKey?: string;
	publicKeyPath?: string;
	validate: boolean;
}

export interface KeyResolver {
	key:
		| ReturnType<typeof createSecretKey>
		| Awaited<ReturnType<typeof importSPKI>>
		| JWTVerifyGetKey;
	algorithms: string[];
}

export async function createKeyResolver(config: JwtKeyConfig): Promise<KeyResolver> {
	if (config.algorithm === "HS256") {
		if (!config.secret) {
			throw new Error("secret is required for HS256");
		}
		const key = createSecretKey(new TextEncoder().encode(config.secret));
		return { key, algorithms: ["HS256"] };
	}

	// Asymmetric algorithms: RS256, ES256, EdDSA
	if (config.jwksUri) {
		const key = createRemoteJWKSet(new URL(config.jwksUri));
		return { key, algorithms: [config.algorithm] };
	}

	if (config.publicKey) {
		const key = await importSPKI(config.publicKey, config.algorithm);
		return { key, algorithms: [config.algorithm] };
	}

	if (config.publicKeyPath) {
		const pem = await readFile(config.publicKeyPath, "utf-8");
		const key = await importSPKI(pem, config.algorithm);
		return { key, algorithms: [config.algorithm] };
	}

	throw new Error("jwksUri or publicKey/publicKeyPath is required for asymmetric algorithms");
}
