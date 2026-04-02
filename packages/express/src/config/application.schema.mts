import { z } from "zod";

const collectorSchema = z
	.object({
		collector: z.string(),
	})
	.passthrough();

export const AppConfigSchema = z.object({
	http: z.object({
		hostname: z.string().default("0.0.0.0"),
		port: z.coerce.number().default(3000),
		pathPrefix: z.string().default(""),
	}),
	oauth: z.object({
		jwt: z.object({
			secret: z.string(),
			validate: z.boolean().default(true),
		}),
	}),
	attribute: z.object({
		collectors: z.array(collectorSchema),
	}),
	rule: z.object({
		collectors: z.array(collectorSchema),
	}),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
