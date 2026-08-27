// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The composition root's logger (#107).
 *
 * The template previously created its logger through `@o3co/auth.utils`, whose
 * shape cannot satisfy the `Logger` port `createApp` accepts — so nothing the
 * template configured ever reached the server's failure events. `createAppLogger`
 * returns a pino instance (newline-delimited JSON on stdout, the shape every
 * log aggregator ingests without a parser), which satisfies the port
 * structurally and honours `logging.level` from the application config.
 */
import type { Logger } from "@o3co/auth.policy-verifier.core";
import { AppConfigSchema } from "@o3co/auth.policy-verifier.server";
import { describe, expect, it } from "vitest";
import { createAppLogger } from "../logger.js";

function configWithLevel(level?: string) {
	return AppConfigSchema.parse({
		oauth: { jwt: { validate: false, allowInsecureDecode: true } },
		attribute: { collectors: [] },
		rule: { collectors: [{ collector: "ResourceActionScopeRuleCollector" }] },
		...(level === undefined ? {} : { logging: { level } }),
	});
}

describe("createAppLogger", () => {
	it("honours logging.level from the application config", () => {
		const logger = createAppLogger(configWithLevel("error"));
		expect(logger.level).toBe("error");
	});

	it("defaults to info when the config does not set a level", () => {
		const logger = createAppLogger(configWithLevel());
		expect(logger.level).toBe("info");
	});

	it("identifies the emitting service in its bindings", () => {
		const logger = createAppLogger(configWithLevel());
		expect(logger.bindings().name).toBe("policy-verifier");
	});

	it("satisfies the Logger port createApp accepts (compile-time + structural check)", () => {
		// The assignment is the compile-time half: a pino instance must satisfy
		// the port with no adapter.
		const logger: Logger = createAppLogger(configWithLevel());
		expect(typeof logger.trace).toBe("function");
		expect(typeof logger.debug).toBe("function");
		expect(typeof logger.info).toBe("function");
		expect(typeof logger.warn).toBe("function");
		expect(typeof logger.error).toBe("function");
		expect(typeof logger.fatal).toBe("function");
		expect(typeof logger.child).toBe("function");
	});
});
