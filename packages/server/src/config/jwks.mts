// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * JWKS transport policy: which endpoints a deployment may fetch signing keys
 * from, and the bounds on that fetch.
 *
 * Whatever the JWKS endpoint serves is trusted wholesale, so every key in it can
 * verify tokens this deployment accepts: the endpoint's identity is the entire
 * trust anchor, and TLS server authentication is what establishes it. Over
 * plaintext http anyone on the network path, or holding a DNS answer,
 * substitutes their own signing key and mints tokens that verify: a full
 * authorization bypass that the verifier's logs cannot tell from ordinary
 * traffic.
 *
 * Dependency-free: `AppConfigSchema` imports it so a rejected URI fails at
 * config-parse time (at boot) instead of at the first request, and config-only
 * consumers of the schema must not pull jose or express in behind it. The
 * `KeyResolverFactory` in `jwt/` re-checks at construction through this same
 * function (AGENTS.md, "Two-Boundary Config Validation"). It lives in `config/`
 * so the dependency runs one way, `jwt/` → `config/`.
 */

import { isLoopbackHost } from "../net/loopback.mjs";
import { NUMERIC_BOUNDS, resolveBound } from "./bounds.mjs";

/**
 * Hosts exempt from the https requirement, named in the rejection message.
 *
 * A loopback address cannot be reached from off the machine, so plaintext costs
 * nothing an attacker with local code execution has not already won; the
 * exemption keeps local development and this repo's tests working against a
 * provider on `localhost` without a certificate. A service reached by container
 * or DNS name (`http://auth-provider:3000`) crosses a network and is rejected.
 */
const LOOPBACK_HOSTS = "localhost, 127.0.0.0/8, [::1]";

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
 * Each admits the string a HOCON env substitution delivers as well as a number:
 * {@link resolveJwksFetchBounds} also runs on hand-built configs, which
 * `createApp` passes straight to the `KeyResolverFactory` and which a consumer
 * assembling one from `process.env` fills with strings.
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

/**
 * Resolves the JWKS fetch bounds for configs that may never have gone through
 * the schema: an absent bound takes its default, and a present one that is not
 * a whole number of milliseconds in range throws, naming the config key the
 * operator wrote. An unparsed string would otherwise reach jose, which ignores a
 * non-number option and silently applies its own default.
 *
 * The specs are the ones in `bounds.mts` that `AppConfigSchema` reads a config
 * file through, so the two boundaries cannot diverge on what a knob admits or on
 * how they say so.
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
		timeoutDuration: resolveBound(config.jwksTimeoutMs, NUMERIC_BOUNDS.jwksTimeoutMs, path),
		cooldownDuration: resolveBound(config.jwksCooldownMs, NUMERIC_BOUNDS.jwksCooldownMs, path),
		cacheMaxAge: resolveBound(config.jwksCacheMaxAgeMs, NUMERIC_BOUNDS.jwksCacheMaxAgeMs, path),
	};
}
