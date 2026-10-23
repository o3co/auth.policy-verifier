// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * How an HS256 secret string becomes HMAC key bytes: `oauth.jwt.secretEncoding`
 * names the reading, and one decoder serves `secret` and every
 * `previousSecrets[].secret`.
 *
 * The readings are auth.provider's `keys.signing.secret-encoding`, byte for
 * byte, so the same string under the same name is the same key on both sides:
 * `utf8` is the text's own bytes, `hex` is whole bytes of hex, `base64` is
 * strict standard base64 (the standard alphabet, padded). A value that is not
 * of the reading named has no bytes, and the check refuses it.
 *
 * `utf8` is the default, the reading this verifier has always applied. An
 * issuer that decodes its secret (auth.provider reads hex, else base64, when
 * its own `secret-encoding` is unset) is paired by naming the same encoding
 * here.
 *
 * Dependency-free: `config/hs256Rotation.mts` and the HS256 `KeyResolverFactory`
 * both reach it, and `AppConfigSchema` reaches it through the former, so a
 * value that does not decode fails at config-parse time (at boot) and at
 * construction of a hand-built config in the same words.
 */

/** The readings `oauth.jwt.secretEncoding` accepts. */
export const SECRET_ENCODINGS = Object.freeze(["utf8", "hex", "base64"] as const);

/** One way of reading a secret string as bytes. */
export type SecretEncoding = (typeof SECRET_ENCODINGS)[number];

/** The reading applied when `secretEncoding` is absent. */
export const DEFAULT_SECRET_ENCODING: SecretEncoding = "utf8";

const HEX = /^(?:[0-9a-fA-F]{2})+$/;

/** Standard base64 alone, padded: a lax decoder skips other characters and reads what is left. */
const STRICT_BASE64 =
	/^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$|^(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$/;

/** The verdict on a `secretEncoding` value: the reading to apply, or why the value is refused. */
export type SecretEncodingCheck =
	| { ok: true; encoding: SecretEncoding }
	| { ok: false; message: string };

/**
 * Resolves `secretEncoding`: absent means {@link DEFAULT_SECRET_ENCODING}, and
 * anything but one of {@link SECRET_ENCODINGS} is refused. Takes `unknown`
 * because a hand-built config is not held to its static type.
 *
 * The message is relative to the `oauth.jwt` block, as the other shared checks'
 * are; each boundary prefixes its own path.
 */
export function checkSecretEncoding(value: unknown): SecretEncodingCheck {
	if (value === undefined) {
		return { ok: true, encoding: DEFAULT_SECRET_ENCODING };
	}
	if (typeof value === "string" && (SECRET_ENCODINGS as readonly string[]).includes(value)) {
		return { ok: true, encoding: value as SecretEncoding };
	}
	return {
		ok: false,
		message: `secretEncoding must be one of ${SECRET_ENCODINGS.map((e) => JSON.stringify(e)).join(", ")}`,
	};
}

/**
 * The bytes of `secret` under `encoding`; `undefined` when the string is not of
 * that reading. It only decodes: it applies no entropy floor and no rotation
 * rules, so a caller holding operator input validates it with
 * `parseHs256Rotation` / `checkHs256Rotation` first (which also return the
 * resolved `secretEncoding`) and decodes what passed.
 *
 * @throws TypeError when `secret` is not a string, which only a caller that
 * ignores the static type can pass.
 */
export function decodeSecret(secret: string, encoding: SecretEncoding): Buffer | undefined {
	if (typeof secret !== "string") {
		throw new TypeError(`decodeSecret: secret must be a string, got ${typeof secret}`);
	}
	switch (encoding) {
		case "utf8":
			return Buffer.from(secret, "utf8");
		case "hex":
			return HEX.test(secret) ? Buffer.from(secret, "hex") : undefined;
		case "base64":
			return STRICT_BASE64.test(secret) ? Buffer.from(secret, "base64") : undefined;
	}
}
