// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * One definition of "loopback" for the whole package.
 *
 * Two seams ask the question, for opposite reasons, and they must not drift
 * apart: the JWKS URI check (#109) exempts loopback from the https requirement
 * because there is no network path to attack, and the bind-address check (#108)
 * treats loopback as the safe default because there is no network path to reach
 * it from. A host either is local by definition or it is not — so the answer
 * lives here, and only the input spelling differs.
 */

/** The whole 127.0.0.0/8 block, not just 127.0.0.1, octets range-checked. */
const LOOPBACK_IPV4 = /^127(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/**
 * True for a hostname that resolves to the local machine by definition, never
 * by lookup. Deliberately an exact test rather than a prefix or suffix one:
 * `localhost.attacker.test` and `127.0.0.1.attacker.test` are ordinary
 * routable names, and treating either as loopback would hand the carve-out to
 * anyone who can register a subdomain.
 *
 * Takes a `URL.hostname`-shaped value: already lowercased, IPv6 literals still
 * bracketed. For a hostname an operator typed into config, use
 * {@link isLoopbackBindAddress}.
 */
export function isLoopbackHost(hostname: string): boolean {
	return hostname === "localhost" || hostname === "[::1]" || LOOPBACK_IPV4.test(hostname);
}

/**
 * True when binding `hostname` makes the port reachable only from this host.
 *
 * The config-shaped counterpart of {@link isLoopbackHost}: this value is what
 * an operator wrote in `http.hostname` and what goes to `server.listen`, so it
 * arrives in whatever case they used, with IPv6 either bracketed (`[::1]`, the
 * URL spelling) or bare (`::1`, the spelling `listen` wants).
 *
 * Anything not recognised as loopback — `0.0.0.0`, `::`, a concrete interface
 * address, a resolvable name, or the empty string Node reads as "all
 * interfaces" — is judged reachable from off-host, so an unrecognised value
 * errs toward warning rather than silence.
 */
export function isLoopbackBindAddress(hostname: string): boolean {
	const normalized = hostname.trim().toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
	return (
		// IPv4-mapped IPv6 — the form a dual-stack listener reports for a v4 peer.
		normalized === "::ffff:127.0.0.1" || isLoopbackHost(normalized === "::1" ? "[::1]" : normalized)
	);
}
