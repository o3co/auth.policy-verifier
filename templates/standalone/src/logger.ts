// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { AppConfig } from "@o3co/auth.policy-verifier.server";
import { pino, stdSerializers } from "pino";

/**
 * The composition root's logger, injected into `createApp` so the verify
 * router's failure events (`jwt_token_rejected`, `jwt_verification_unavailable`,
 * `verify_internal_error`) reach an aggregator-ready sink.
 *
 * pino, emitting newline-delimited JSON on stdout, which log aggregators ingest
 * without a parser. The `Logger` port carries pino's two-overload call
 * signature, so a pino instance satisfies it with no adapter. pino drops
 * sub-threshold calls before formatting, so `logging.level` costs nothing for
 * the levels it excludes. The auth.provider standalone template wires the
 * same, so one aggregator pipeline serves the whole stack.
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
