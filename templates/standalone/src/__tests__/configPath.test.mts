// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { resolveConfigPaths } from "../configPath.mts";

describe("resolveConfigPaths", () => {
	it("accepts a configDirPath with a trailing slash", () => {
		const { applicationConfPath, envConfPath } = resolveConfigPaths(
			"/home/node/templates/standalone/config/",
			"production",
		);
		expect(applicationConfPath).toBe("/home/node/templates/standalone/config/application.conf");
		expect(envConfPath).toBe("/home/node/templates/standalone/config/production.conf");
	});

	it("accepts a configDirPath without a trailing slash", () => {
		const { applicationConfPath, envConfPath } = resolveConfigPaths(
			"/home/node/templates/standalone/config",
			"development",
		);
		expect(applicationConfPath).toBe("/home/node/templates/standalone/config/application.conf");
		expect(envConfPath).toBe("/home/node/templates/standalone/config/development.conf");
	});

	it("rejects env names that resolve outside configDirPath", () => {
		expect(() =>
			resolveConfigPaths("/home/node/templates/standalone/config/", "../secrets"),
		).toThrow(/resolves outside/);
	});

	it("rejects env names containing a path separator", () => {
		expect(() =>
			resolveConfigPaths("/home/node/templates/standalone/config/", "nested/env"),
		).toThrow(/resolves outside/);
	});
});
