/*
 * Standalone entrypoint — creates and starts the policy-verifier server.
 */
import { createApp } from "./app.mjs";

const PORT = Number(process.env.HTTP_PORT ?? 3000);
const HOSTNAME = process.env.HTTP_HOSTNAME ?? "0.0.0.0";

const app = await createApp();

app.listen(PORT, HOSTNAME, () => {
	console.log(`policy-verifier listening on http://${HOSTNAME}:${PORT}`);
});
