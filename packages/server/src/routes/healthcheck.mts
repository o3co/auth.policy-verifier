// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import express from "express";

/**
 * Liveness probe router, mounted once per path this server answers on.
 *
 * Moved in from `@o3co/auth.utils/express`, whose default path was
 * `/healthcheck` — the very reason this server answered on a different path
 * from `auth.provider` and `auth.proxy` until 0.7.0 added the canonical
 * `/_healthcheck` alongside it. A shared default that each component then has
 * to override is not a shared decision; the paths this server answers on live
 * in `app.mts`, and this builds a router for one of them.
 *
 * Liveness only: it says the process is up and the event loop is turning, not
 * that any key resolver or collector can reach what it depends on.
 */
export function createHealthcheckRouter(path: string): express.Router {
	const router = express.Router();
	router.get(path, (_req, res) => {
		res.status(200).json({ status: "ok" });
	});
	return router;
}
