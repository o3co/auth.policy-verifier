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
		jwt: z
			.object({
				algorithm: z.enum(["HS256", "RS256", "ES256", "EdDSA"]).default("HS256"),
				secret: z.string().optional(),
				jwksUri: z.string().optional(),
				publicKey: z.string().optional(),
				publicKeyPath: z.string().optional(),
				validate: z.boolean().default(true),
			})
			.superRefine((data, ctx) => {
				if (!data.validate) return; // skip validation when disabled
				if (data.algorithm === "HS256" && !data.secret) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "secret is required for HS256",
					});
				}
				const isAsymmetric = ["RS256", "ES256", "EdDSA"].includes(data.algorithm);
				if (isAsymmetric && !data.jwksUri && !data.publicKey && !data.publicKeyPath) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "jwksUri or publicKey/publicKeyPath is required for asymmetric algorithms",
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
