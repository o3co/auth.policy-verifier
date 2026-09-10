// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	JWT_MODE_MIGRATION_MESSAGE,
	JWT_MODE_REMOVED_KEYS,
} from "../config/application.schema.mjs";
import { assertConfigObject } from "../config/assertConfigObject.mjs";
import { JWT_TOKEN_AUTHENTICATOR } from "../config/tokenAuthenticatorSelection.mjs";
import type { TokenAuthenticatorFactory } from "./keyResolver.mjs";
import {
	assertVerifyRouterJwtConfig,
	createTokenAuthenticator,
	resolveJwtTimeClaimBounds,
	type VerifyRouterJwtConfig,
} from "./tokenAuthenticator.mjs";

export { JWT_TOKEN_AUTHENTICATOR };

/**
 * The built-in token authenticator: bearer JWTs verified against `oauth.jwt`
 * (#219). `createApp` registers it under {@link JWT_TOKEN_AUTHENTICATOR}
 * before any module runs, so it is always selectable and never replaceable —
 * a deployment that authenticates some other way registers its own factory
 * under its own name and selects it with `oauth.authenticator`.
 *
 * This is the step that mapped the wire `oauth.jwt.mode` onto the router's
 * internal discriminated union (#134), moved behind the port unchanged.
 * `AppConfigSchema` already enforces the wire invariants (the mode enum,
 * iss/aud/typ presence, rejection of the removed keys) for schema-validated
 * configs; everything is re-checked here (#106) — see AGENTS.md, "Two-Boundary
 * Config Validation" — with the `oauth.jwt.*` paths the operator actually
 * wrote. The messages keep naming `createApp`, because that is the boundary
 * running this factory.
 *
 * Shape first: a hand-built config can carry anything at these paths, and the
 * key checks below reach into the block with `in` and object spread, which
 * throw a bare TypeError on a primitive. Report a malformed block like every
 * other boundary failure instead of leaking that TypeError.
 */
export const JwtTokenAuthenticatorFactory: TokenAuthenticatorFactory = async (
	oauth,
	{ logger, keyResolverRegistry },
) => {
	assertConfigObject(oauth, "oauth");
	assertConfigObject(oauth.jwt, "oauth.jwt");
	const jwtWire = oauth.jwt;
	for (const staleKey of JWT_MODE_REMOVED_KEYS) {
		if (staleKey in jwtWire) {
			// A pre-#134 config must not be silently reinterpreted: a defaulted
			// mode would mean verify even where the operator had opted into
			// decode-only. Fail with the same migration message the schema emits.
			throw new Error(`createApp: ${JWT_MODE_MIGRATION_MESSAGE}`);
		}
	}
	// Hand-built configs may omit `mode`; they get the schema's default (verify).
	const mode: unknown = jwtWire.mode ?? "verify";
	// Ahead of the mode split, because the token lifetime bounds (#110) apply in
	// both modes — the decode path restates them by hand rather than skipping
	// them — and resolving here is what lets a bad value be reported against the
	// `oauth.jwt.*` key the operator actually wrote.
	const timeClaims = resolveJwtTimeClaimBounds(jwtWire, "oauth.jwt");
	const bounds = {
		maxTokenAgeSeconds: timeClaims.maxTokenAge,
		clockToleranceSeconds: timeClaims.clockTolerance,
	};
	let jwt: VerifyRouterJwtConfig;
	if (mode === "verify") {
		const verifying = { ...jwtWire, validate: true as const };
		assertVerifyRouterJwtConfig(verifying, {
			caller: "createApp",
			path: "oauth.jwt",
			verifyCondition: 'oauth.jwt.mode is "verify"',
		});
		const algorithm = jwtWire.algorithm;
		if (typeof algorithm !== "string" || algorithm === "") {
			throw new Error("createApp: oauth.jwt.algorithm must be a non-empty string");
		}
		const keyResolver = await keyResolverRegistry.get(algorithm)(jwtWire);
		jwt = {
			validate: true,
			key: keyResolver.key,
			algorithms: keyResolver.algorithms,
			issuer: verifying.issuer,
			audience: verifying.audience,
			// #219: validated by the guard above; `undefined` means `aud`.
			audienceClaim: jwtWire.audienceClaim as string | undefined,
			tokenType: verifying.tokenType,
			...bounds,
		};
	} else if (mode === "insecure-decode") {
		// The mode string is the consent — see the schema's `mode` doc comment.
		jwt = { validate: false, allowInsecureDecode: true, ...bounds };
		// error, not warn: a deployment that reaches this line accepts unsigned
		// tokens, and a fleet filtering at level=error must still see it (#106).
		logger.error({ mode: "insecure-decode" }, "jwt_validation_disabled");
	} else {
		throw new Error(
			`createApp: oauth.jwt.mode must be "verify" or "insecure-decode", got ${JSON.stringify(mode)}`,
		);
	}
	return createTokenAuthenticator(jwt, logger);
};
