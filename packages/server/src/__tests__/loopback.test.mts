// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { isLoopbackBindAddress, isLoopbackHost } from "#/net/loopback.mjs";

describe("isLoopbackHost", () => {
	// URL.hostname shape: already lowercased, IPv6 literals still bracketed.
	it.each(["localhost", "127.0.0.1", "127.0.0.2", "127.255.255.255", "[::1]"])(
		"treats %s as loopback",
		(hostname) => {
			expect(isLoopbackHost(hostname)).toBe(true);
		},
	);

	it.each([
		"0.0.0.0",
		"10.0.0.5",
		"auth-provider",
		// The carve-out must not be reachable by registering a subdomain.
		"localhost.attacker.test",
		"127.0.0.1.attacker.test",
		// Octets are range-checked, so a malformed dotted quad is not loopback.
		"127.999.0.1",
		"::1",
	])("treats %s as routable", (hostname) => {
		expect(isLoopbackHost(hostname)).toBe(false);
	});
});

describe("isLoopbackBindAddress", () => {
	// Config shape: whatever case the operator typed, IPv6 bracketed or bare.
	it.each([
		"127.0.0.1",
		"127.1.2.3",
		"127.255.255.255",
		"localhost",
		"LOCALHOST",
		"  127.0.0.1  ",
		"::1",
		"[::1]",
		"::ffff:127.0.0.1",
	])("treats %s as loopback", (hostname) => {
		expect(isLoopbackBindAddress(hostname)).toBe(true);
	});

	it.each([
		"0.0.0.0",
		"::",
		"[::]",
		"10.0.0.5",
		"verifier.internal",
		// Node reads an empty bind address as "all interfaces".
		"",
		// Range-checked: not a valid 127.0.0.0/8 address, so err toward warning.
		"127.999.0.1",
	])("treats %s as reachable from off-host", (hostname) => {
		expect(isLoopbackBindAddress(hostname)).toBe(false);
	});
});
