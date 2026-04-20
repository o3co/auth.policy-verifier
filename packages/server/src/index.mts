// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

export { type CreateAppOptions, createApp } from "./app.mjs";
export { type AppConfig, AppConfigSchema } from "./config/application.schema.mjs";
export {
	builtinKeyResolversModule,
	EdDSAKeyResolverFactory,
	ES256KeyResolverFactory,
	HS256KeyResolverFactory,
	RS256KeyResolverFactory,
} from "./jwt/index.mjs";
export { createVerifyRouter, type VerifyRouterConfig } from "./routes/verify.mjs";
