/*
 * Standalone entrypoint — creates and starts the policy-verifier server.
 */
import { resolve } from "node:path";
import { createLogger, gracefulShutdown } from "@o3co/auth.utils";
import { createApp } from "@o3co/auth.policy-verifier.express";

const logger = createLogger("policy-verifier");

const PORT = Number(process.env.HTTP_PORT ?? 3000);
const HOSTNAME = process.env.HTTP_HOSTNAME ?? "0.0.0.0";

const configPath = resolve(import.meta.dirname, "../config/application.conf");
const app = await createApp({ configPath });

const server = app.listen(PORT, HOSTNAME, () => {
	logger.info(`listening on http://${HOSTNAME}:${PORT}`);
});

gracefulShutdown(server);
