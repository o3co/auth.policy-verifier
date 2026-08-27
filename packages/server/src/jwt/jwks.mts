// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * JWKS transport policy (#109): which endpoints a deployment may fetch signing
 * keys from, and the bounds on that fetch.
 *
 * Trust assumption — what requiring https buys, and all it buys: whatever the
 * JWKS endpoint serves is trusted wholesale, so every key in that document can
 * verify tokens this deployment accepts. The identity of the endpoint is
 * therefore the entire trust anchor, and TLS server authentication is what
 * establishes it. Over plaintext http anyone on the network path — or holding
 * a DNS answer — substitutes their own signing key and mints tokens that
 * verify: a full authorization bypass, with nothing in the verifier's logs to
 * distinguish it from ordinary traffic.
 *
 * Deliberately dependency-free: `AppConfigSchema` imports it so a rejected URI
 * fails at config-parse time (at boot, where an operator sees it) instead of at
 * the first request, and config-only consumers of the schema must not pull jose
 * or express in behind it. The `KeyResolverFactory` re-checks at construction
 * for hand-built configs that never went through the schema — the same division
 * of labor as `assertVerifyRouterJwtConfig`.
 */

import {
	DEFAULT_JWKS_CACHE_MAX_AGE_MS,
	DEFAULT_JWKS_COOLDOWN_MS,
	DEFAULT_JWKS_TIMEOUT_MS,
} from "../config/defaults.mjs";

/**
 * Hosts exempt from the https requirement, named in the rejection message.
 *
 * The carve-out exists because a loopback address cannot be reached from off
 * the machine: there is no network path to sit on, so plaintext costs nothing
 * an attacker with local code execution has not already won. It keeps local
 * development and this repo's own tests working against a provider on
 * `localhost` without a certificate. A service reached by container or DNS name
 * (`http://auth-provider:3000`) is *not* loopback — that traffic crosses a
 * network — and is rejected.
 */
const LOOPBACK_HOSTS = "localhost, 127.0.0.0/8, [::1]";

/** The whole 127.0.0.0/8 block, not just 127.0.0.1, octets range-checked. */
const LOOPBACK_IPV4 = /^127(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/**
 * True for a hostname that resolves to the local machine by definition, never
 * by lookup. Deliberately an exact test rather than a prefix or suffix one:
 * `localhost.attacker.test` and `127.0.0.1.attacker.test` are ordinary
 * routable names, and treating either as loopback would hand the carve-out to
 * anyone who can register a subdomain.
 */
function isLoopbackHost(hostname: string): boolean {
	// `URL.hostname` is already lowercased and keeps IPv6 literals bracketed.
	return hostname === "localhost" || hostname === "[::1]" || LOOPBACK_IPV4.test(hostname);
}

/**
 * Outcome of {@link checkJwksUri}: the parsed URL, or the operator-facing
 * reason it was refused. A result rather than a throw because the schema
 * reports it as one zod issue among others, at the `jwksUri` path.
 */
export type JwksUriCheck = { ok: true; url: URL } | { ok: false; message: string };

/**
 * Applies the transport policy to a configured JWKS URI: https anywhere, and
 * plaintext http only for the loopback hosts listed in {@link LOOPBACK_HOSTS}.
 * Every other scheme (`file:`, `ftp:`, `data:`, …) is refused — a key source
 * that is not an authenticated remote fetch is not a JWKS endpoint.
 */
export function checkJwksUri(jwksUri: string): JwksUriCheck {
	if (!URL.canParse(jwksUri)) {
		return {
			ok: false,
			message: `jwksUri must be an absolute URL, got ${JSON.stringify(jwksUri)}`,
		};
	}
	const url = new URL(jwksUri);
	if (url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHost(url.hostname))) {
		return { ok: true, url };
	}
	return {
		ok: false,
		message:
			`jwksUri must use https; http is accepted only for loopback hosts (${LOOPBACK_HOSTS}), ` +
			`got ${JSON.stringify(jwksUri)}`,
	};
}

/**
 * {@link checkJwksUri} for callers that cannot collect issues — throws the same
 * message the schema reports, so both boundaries say the same thing.
 */
export function parseJwksUri(jwksUri: string): URL {
	const checked = checkJwksUri(jwksUri);
	if (!checked.ok) {
		throw new Error(checked.message);
	}
	return checked.url;
}

/**
 * JWKS fetch knobs an operator may set on `oauth.jwt`.
 *
 * Each admits the string a HOCON env substitution delivers as well as a number,
 * because {@link resolveJwksFetchBounds} runs on unparsed configs too: `createApp`
 * accepts hand-built config objects and passes the JWT block straight to the
 * `KeyResolverFactory`, so a consumer assembling one from `process.env` supplies
 * strings. `AppConfigSchema` coerces them for config files; the resolver coerces
 * them for everyone else.
 */
export interface JwksFetchConfig {
	/** Abort a JWKS fetch after this long (ms). Positive integer. */
	jwksTimeoutMs?: number | string;
	/** Minimum spacing between JWKS fetches (ms). Non-negative integer. */
	jwksCooldownMs?: number | string;
	/** How long a fetched JWKS is served from cache (ms). Positive integer. */
	jwksCacheMaxAgeMs?: number | string;
}

/**
 * The bounds handed to jose's `createRemoteJWKSet`. Structural rather than
 * jose's `RemoteJWKSetOptions` so this module stays importable from the config
 * layer without dragging jose along.
 */
export interface JwksFetchBounds {
	timeoutDuration: number;
	cooldownDuration: number;
	cacheMaxAge: number;
}

/** Renders a rejected value for an error message: `JSON.stringify` turns NaN into `null`. */
function describeValue(value: unknown): string {
	if (typeof value === "string") {
		return JSON.stringify(value);
	}
	if (value === null || typeof value !== "object") {
		return String(value);
	}
	return Array.isArray(value) ? "an array" : "an object";
}

/**
 * Validates one bound, coercing the string form on the way. Only numbers and
 * strings are coerced: `Number(true)` is 1 and `Number(null)` is 0, so running
 * anything else through `Number` would invent a bound the operator never wrote.
 * Non-integers, NaN and Infinity are refused for the same reason the schema
 * refuses them — a bound that cannot be stated in whole milliseconds is a
 * mistake, and `Infinity` is exactly the unbounded fetch this guards against.
 */
function resolveBound(
	value: unknown,
	field: keyof JwksFetchConfig,
	path: string,
	fallback: number,
	minimum: 0 | 1,
): number {
	if (value === undefined) {
		return fallback;
	}
	const numeric =
		typeof value === "number" || typeof value === "string" ? Number(value) : Number.NaN;
	if (!Number.isInteger(numeric) || numeric < minimum) {
		const requirement = minimum === 0 ? "a non-negative integer" : "a positive integer";
		throw new Error(
			`${path}.${field} must be ${requirement} number of milliseconds, got ${describeValue(value)}`,
		);
	}
	return numeric;
}

/**
 * Resolves the JWKS fetch bounds, falling back to the defaults for anything the
 * config omits — hand-built configs never went through the schema, so the
 * defaults have to hold here too, and so does the validation `AppConfigSchema`
 * performs for config files: an unparsed string would otherwise reach jose,
 * which ignores a non-number option and silently applies its own default. An
 * absent bound defaults; a present one that is not a whole number of
 * milliseconds in range throws, naming the config key the operator wrote.
 *
 * @param path Config path of the JWT block at the calling boundary. `createApp`
 * hands the `oauth.jwt` block to the `KeyResolverFactory`, so that is the
 * default; a custom factory reached by another path passes its own.
 */
export function resolveJwksFetchBounds(
	config: JwksFetchConfig,
	path = "oauth.jwt",
): JwksFetchBounds {
	return {
		timeoutDuration: resolveBound(
			config.jwksTimeoutMs,
			"jwksTimeoutMs",
			path,
			DEFAULT_JWKS_TIMEOUT_MS,
			1,
		),
		// Zero is a valid cooldown ("refetch on every miss"), so the floor is 0 and
		// the absent case is told apart by `undefined`, never by falsiness.
		cooldownDuration: resolveBound(
			config.jwksCooldownMs,
			"jwksCooldownMs",
			path,
			DEFAULT_JWKS_COOLDOWN_MS,
			0,
		),
		cacheMaxAge: resolveBound(
			config.jwksCacheMaxAgeMs,
			"jwksCacheMaxAgeMs",
			path,
			DEFAULT_JWKS_CACHE_MAX_AGE_MS,
			1,
		),
	};
}
