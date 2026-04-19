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
import {
	type AttributeCollectorFactory,
	type KeyResolverFactory,
	Registry,
	type ResourceParserFactory,
	type RuleCollectorFactory,
} from "@o3co/auth.policy-verifier.core";
import { exportSPKI } from "jose";
import { describe, expect, it } from "vitest";
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
