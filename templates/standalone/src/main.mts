// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Standalone entrypoint — creates and starts the policy-verifier server.
 */
import { resolve } from "node:path";
import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
import {
	AppConfigSchema,
	builtinKeyResolversModule,
	createApp,
} from "@o3co/auth.policy-verifier.server";
import { createLogger, gracefulShutdown } from "@o3co/auth.utils";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";

const logger = createLogger("policy-verifier");

const config = validate(
	parseFile(resolve(import.meta.dirname, "../config/application.conf")),
	AppConfigSchema,
);

const app = await createApp({
	pathResolver: import.meta.resolve,
	config,
	modules: [builtinCollectorsModule, builtinKeyResolversModule],
});

const server = app.listen(config.http.port, config.http.hostname, () => {
	logger.info(`listening on http://${config.http.hostname}:${config.http.port}`);
});

gracefulShutdown(server);
