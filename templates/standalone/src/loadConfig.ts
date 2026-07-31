// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { type AppConfig, AppConfigSchema } from "@o3co/auth.policy-verifier.server";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { resolveConfigPaths } from "./configPath.js";

/**
 * Loads the validated application config for `env` from `configDirPath`.
 *
 * The `<env>.conf` overlay is layered over `application.conf`. An overlay that
 * declares nothing (the shipped development/production files are comments
 * only) is an empty HOCON document and falls through to the base layer.
 */
export function loadAppConfig(configDirPath: string, env: string): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDirPath, env);
	return validate(
		parseFile(envConfPath).withFallback(parseFile(applicationConfPath)),
		AppConfigSchema,
	);
}
