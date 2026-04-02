/*
 * Standalone entrypoint — creates and starts the policy-verifier server.
 */
import { createLogger, gracefulShutdown } from "@o3co/auth.utils";
import { createApp } from "./app.mjs";

const logger = createLogger("policy-verifier");

const PORT = Number(process.env.HTTP_PORT ?? 3000);
const HOSTNAME = process.env.HTTP_HOSTNAME ?? "0.0.0.0";

const app = await createApp();

const server = app.listen(PORT, HOSTNAME, () => {
	logger.info(`listening on http://${HOSTNAME}:${PORT}`);
});

gracefulShutdown(server);
