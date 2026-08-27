// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { AppConfig } from "@o3co/auth.policy-verifier.server";
import { pino, stdSerializers } from "pino";

/**
 * The composition root's logger, injected into `createApp` so the verify
 * router's failure events (`jwt_token_rejected`, `jwt_verification_unavailable`,
 * `verify_internal_error`) reach an aggregator-ready sink (#107).
 *
 * pino, emitting newline-delimited JSON on stdout — the shape every log
 * aggregator ingests without a parser, and the reason the `Logger` port carries
 * pino's two-overload call signature. A pino instance therefore satisfies the
 * port structurally, with no adapter. pino drops sub-threshold calls before
 * formatting, so `logging.level` is honoured at zero cost for the levels it
 * excludes.
 *
 * The same wiring exists in the auth.provider standalone template; keeping the
 * two composition roots symmetric is what lets one aggregator pipeline serve
 * the whole stack.
 */
export function createAppLogger(config: AppConfig) {
	return pino({
		name: "policy-verifier",
		level: config.logging.level,
		// `err` is pino's conventional key for an Error, and every structured
		// event in this stack uses it — `logger.error({ err }, "…_error")`.
		// Without the serialiser an Error stringifies to `{}` and the stack is
		// lost exactly where it is needed.
		serializers: { err: stdSerializers.err },
	});
}
