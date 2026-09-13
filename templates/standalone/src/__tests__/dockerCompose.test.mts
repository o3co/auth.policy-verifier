// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const compose = readFileSync(new URL("../../docker-compose.yml", import.meta.url), "utf8");

describe("docker-compose.yml — the cedar profile's agent is authenticated (v0.10.0 audit)", () => {
	it("starts the agent with the token the app sends", () => {
		// An unauthenticated cedar-agent is a write oracle over the policy set:
		// anything that reaches its port can PUT `permit(principal, action,
		// resource);`. The token comes from the same CEDAR_AUTHENTICATION the app
		// reads, so the two cannot disagree.
		expect(compose).toMatch(/- CEDAR_AGENT_AUTHENTICATION=\$\{CEDAR_AUTHENTICATION:-\}/);
		// And the app from the same interpolation, not only through `env_file`:
		// a shell variable or `--env-file` would otherwise reach the agent alone
		// (review).
		expect(compose).toMatch(/- CEDAR_AUTHENTICATION=\$\{CEDAR_AUTHENTICATION:-\}/);
	});

	it("does not make a plain `docker compose up` depend on it", () => {
		// `${VAR:?}` is interpolated for every service, profile or not, so it
		// would refuse the app-only stack too. Unset, the agent is started with
		// an empty token, refuses every call, and the verifier's boot names
		// CEDAR_AUTHENTICATION — closed, without breaking the default stack.
		expect(compose).not.toMatch(/:\?/);
	});
});
