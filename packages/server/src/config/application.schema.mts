import { z } from "zod";

const collectorSchema = z
	.object({
		collector: z.string(),
	})
	.passthrough();

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
			})
			.passthrough()
			.superRefine((data, ctx) => {
				if (!data.validate) return; // skip validation when disabled
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
	}),
	resource: z
		.object({
			parser: z.string().default("DotNotationResourceParser"),
		})
		.default(() => ({ parser: "DotNotationResourceParser" })),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
