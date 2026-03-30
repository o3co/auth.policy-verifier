import express from "express";

export function createHealthcheckRouter(): express.Router {
	const router = express.Router();
	router.get("/healthcheck", (_req, res) => {
		res.status(200).json({ status: "ok" });
	});
	return router;
}
