// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Standalone entrypoint — creates and starts the policy-verifier server.
 */
import { fileURLToPath } from "node:url";
import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
import { builtinKeyResolversModule, createApp } from "@o3co/auth.policy-verifier.server";
import { gracefulShutdown } from "@o3co/auth.utils";
import { loadAppConfig } from "./loadConfig.js";
import { createAppLogger } from "./logger.js";

const env = process.env.CONFIG_ENV || process.env.NODE_ENV || "development";
const configDir = new URL("../config/", import.meta.url);
const configDirPath = fileURLToPath(configDir);

const config = loadAppConfig(configDirPath, env);
const logger = createAppLogger(config);

const app = await createApp({
	pathResolver: import.meta.resolve,
	config,
	modules: [builtinCollectorsModule, builtinKeyResolversModule],
	logger,
});

const server = app.listen(config.http.port, config.http.hostname, () => {
	logger.info(`listening on http://${config.http.hostname}:${config.http.port}`);
});

gracefulShutdown(server);
