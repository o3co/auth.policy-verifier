/*
 * Standalone entrypoint — creates and starts the policy-verifier server.
 */
import { resolve } from "node:path";
import { AppConfigSchema, createApp } from "@o3co/auth.policy-verifier.express";
import { createLogger, gracefulShutdown } from "@o3co/auth.utils";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";

const logger = createLogger("policy-verifier");

const configPath = resolve(import.meta.dirname, "../config/application.conf");
const config = validate(parseFile(configPath), AppConfigSchema);

const app = await createApp({ config });

const server = app.listen(config.http.port, config.http.hostname, () => {
	logger.info(`listening on http://${config.http.hostname}:${config.http.port}`);
});

gracefulShutdown(server);
