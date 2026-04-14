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

import { generateKeyPair } from "node:crypto";
import { promisify } from "node:util";
import { exportSPKI } from "jose";
import { describe, expect, it } from "vitest";
import { createKeyResolver } from "#/jwt/createKeyResolver.mjs";

const generateKeyPairAsync = promisify(generateKeyPair);

describe("createKeyResolver", () => {
	it("creates HS256 resolver from secret", async () => {
		const resolver = await createKeyResolver({
			algorithm: "HS256",
			secret: "test-secret",
			validate: true,
		});

		expect(resolver.algorithms).toEqual(["HS256"]);
		// key should be a KeyObject (from createSecretKey)
		expect(resolver.key).toBeDefined();
		expect(typeof resolver.key).toBe("object");
	});

	it("creates RS256 resolver from publicKey PEM", async () => {
		const { publicKey } = await generateKeyPairAsync("rsa", { modulusLength: 2048 });
		const pem = await exportSPKI(publicKey as unknown as CryptoKey);

		const resolver = await createKeyResolver({
			algorithm: "RS256",
			publicKey: pem,
			validate: true,
		});

		expect(resolver.algorithms).toEqual(["RS256"]);
		expect(resolver.key).toBeDefined();
	});

	it("creates EdDSA resolver from publicKey PEM", async () => {
		const { publicKey } = await generateKeyPairAsync("ed25519");
		const pem = await exportSPKI(publicKey as unknown as CryptoKey);

		const resolver = await createKeyResolver({
			algorithm: "EdDSA",
			publicKey: pem,
			validate: true,
		});

		expect(resolver.algorithms).toEqual(["EdDSA"]);
		expect(resolver.key).toBeDefined();
	});

	it("creates JWKS resolver from jwksUri (returns function type)", async () => {
		const resolver = await createKeyResolver({
			algorithm: "RS256",
			jwksUri: "https://example.com/.well-known/jwks.json",
			validate: true,
		});

		expect(resolver.algorithms).toEqual(["RS256"]);
		// JWKS resolver is a function
		expect(typeof resolver.key).toBe("function");
	});

	it("throws when HS256 has no secret", async () => {
		await expect(
			createKeyResolver({
				algorithm: "HS256",
				validate: true,
			}),
		).rejects.toThrow("secret is required for HS256");
	});

	it("throws when asymmetric has no key source", async () => {
		await expect(
			createKeyResolver({
				algorithm: "RS256",
				validate: true,
			}),
		).rejects.toThrow("jwksUri or publicKey/publicKeyPath is required for asymmetric algorithms");
	});
});
