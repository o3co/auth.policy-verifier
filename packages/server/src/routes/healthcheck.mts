// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The liveness-probe router.
 */

import express from "express";

/**
 * Liveness probe router for one path. The paths this server answers on live
 * in `app.mts`, which mounts one of these per path.
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
