// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

const collectorSchema = z
	.object({
		collector: z.string(),
	})
	.passthrough();

/**
 * Zod schema for the HOCON-loaded application configuration. Validates the
 * shape of `http`, `oauth.jwt`, `attribute.collectors`, `rule.collectors`, and
 * `resource.parser`. `.passthrough()` on nested objects lets custom collector
 * and factory configs add their own fields without schema edits.
 *
 * Built-in JWT algorithms (HS256 / RS256 / ES256 / EdDSA) carry extra
 * `superRefine` validation for their required key material. Unknown algorithm
 * names pass schema validation and are expected to validate themselves in
 * their `KeyResolverFactory`.
 */
export const AppConfigSchema = z.object({
	http: z
		.object({
			hostname: z.string().default("0.0.0.0"),
			port: z.coerce.number().default(3000),
			pathPrefix: z.string().default(""),
		})
		.default(() => ({ hostname: "0.0.0.0", port: 3000, pathPrefix: "" })),
	oauth: z.object({
		// Algorithm names are free-form strings so user-registered algorithms can be selected
		// from config without editing the schema enum. Built-in algorithms keep schema-level
		// validation below (via superRefine) so misconfigurations fail at config-parse time.
		// Custom algorithms are expected to validate their own config in their factory.
		jwt: z
			.object({
				algorithm: z.string().default("HS256"),
				secret: z.string().optional(),
				jwksUri: z.string().optional(),
				publicKey: z.string().optional(),
				publicKeyPath: z.string().optional(),
				validate: z.boolean().default(true),
				// RFC 9068 §4 — a resource server validates iss and aud, not just the
				// signature. Both are required whenever `validate` is on (see superRefine).
				issuer: z.union([z.string(), z.array(z.string())]).optional(),
				audience: z.union([z.string(), z.array(z.string())]).optional(),
				// Accepted `typ` header. `at+jwt` is the RFC 9068 access-token type; pinning
				// it rejects id_tokens, refresh tokens and logout tokens signed with the same key.
				tokenType: z.string().default("at+jwt"),
			})
			.passthrough()
			.superRefine((data, ctx) => {
				if (!data.validate) return; // skip validation when disabled
				const issuers = Array.isArray(data.issuer) ? data.issuer : [data.issuer];
				const audiences = Array.isArray(data.audience) ? data.audience : [data.audience];
				if (issuers.length === 0 || issuers.some((i) => !i)) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "issuer is required when validate is true (RFC 9068 §4)",
						path: ["issuer"],
					});
				}
				if (audiences.length === 0 || audiences.some((a) => !a)) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "audience is required when validate is true (RFC 9068 §4)",
						path: ["audience"],
					});
				}
				if (!data.tokenType) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "tokenType must not be empty when validate is true (RFC 9068 §4)",
						path: ["tokenType"],
					});
				}
				if (data.algorithm === "HS256" && !data.secret) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "secret is required for HS256",
					});
				}
				const isBuiltinAsymmetric = ["RS256", "ES256", "EdDSA"].includes(data.algorithm);
				if (isBuiltinAsymmetric && !data.jwksUri && !data.publicKey && !data.publicKeyPath) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: `jwksUri or publicKey/publicKeyPath is required for ${data.algorithm}`,
					});
				}
			}),
	}),
	attribute: z.object({
		collectors: z.array(collectorSchema),
	}),
	rule: z.object({
		collectors: z.array(collectorSchema),
		// Decision for a request that collects no rules. "deny" (default) keeps the
		// engine fail-closed; "allow" is an explicit per-deployment opt-out.
		onEmptyRuleSet: z.enum(["deny", "allow"]).default("deny"),
	}),
	resource: z
		.object({
			parser: z.string().default("DotNotationResourceParser"),
		})
		.default(() => ({ parser: "DotNotationResourceParser" })),
	verify: z
		.object({
			// Cap on `POST /verify/batch` entries. The batch endpoint exists so
			// filtering a list of N resources is one round trip; the cap keeps one
			// request from turning into an unbounded amount of pipeline work.
			maxBatchSize: z.coerce.number().int().positive().default(50),
		})
		.default(() => ({ maxBatchSize: 50 })),
	// Defaulted (not shape-only): deployments mount an overlay config OVER the
	// template's application.conf, so a section the overlay does not repeat is
	// simply absent. `silent` is a threshold, not a level anything emits at.
	logging: z
		.object({
			level: z.enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"]).default("info"),
		})
		.default(() => ({ level: "info" as const })),
});

/** Type inferred from `AppConfigSchema`. Consumed by `createApp`. */
export type AppConfig = z.infer<typeof AppConfigSchema>;
