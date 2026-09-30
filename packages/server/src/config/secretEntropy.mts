// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * How much key material an operator-supplied shared secret actually carries,
 * and how to say so when it is not enough.
 *
 * HS256 is this project's default algorithm, and a symmetric secret is not
 * merely a key that reads tokens: the same value signs them, so anyone who
 * guesses it mints tokens for any subject.
 *
 * The measurement is auth.provider's, ported rather than reinvented.
 * `MIN_SECRET_ENTROPY_BYTES` in `config/defaults.mts` records why the two
 * services must agree on the floor; agreeing on the number is not enough on its
 * own. A verifier that measured a value differently from the provider would
 * reject secrets the provider had just told the operator were fine, so the
 * reading below is the same reading, down to its treatment of malformed base64
 * padding.
 *
 * Dependency-free: `AppConfigSchema` reaches it through
 * `config/hs256Rotation.mts`, so a weak secret fails at config-parse time (at
 * boot) rather than at the first request, and config-only consumers of the
 * schema must not pull jose or express in behind it.
 */

import { MIN_SECRET_ENTROPY_BYTES } from "./defaults.mjs";

/** Decoded byte length if `value` is a well-formed hex string, else undefined. */
function hexByteLength(value: string): number | undefined {
	if (value.length === 0 || value.length % 2 !== 0) return undefined;
	if (!/^[0-9a-fA-F]+$/.test(value)) return undefined;
	return value.length / 2;
}

/**
 * Decoded byte length if `value` is a well-formed base64 / base64url string,
 * else undefined.
 *
 * Hand-rolled because `Buffer.from(value, "base64")` is lenient: it silently
 * drops characters outside the alphabet, so it answers for a string that is not
 * base64 at all, and answers *small*, which would reject good passphrases.
 *
 * Padding is held to the same standard as the alphabet: zero, one or two `=`,
 * and only where the body length calls for it (one after a 3-character final
 * group, two after a 2-character one). `"abcd===="` and `"abcd="` are not
 * base64, so the raw-bytes reading stands for them. Trimming any run of `=`
 * instead would score a passphrase that merely ends in equals signs at
 * three-quarters of its real length: fail-closed, but a usability trap.
 */
function base64ByteLength(value: string): number | undefined {
	// Count the trailing '=' run without assuming it is well-formed.
	const padding = value.length - value.replace(/=+$/, "").length;
	if (padding > 2) return undefined;
	const body = value.slice(0, value.length - padding);
	if (body.length === 0) return undefined;
	// Standard (`+/`) and URL-safe (`-_`) alphabets; a value mixing the two is
	// not a valid encoding in either.
	if (!/^[A-Za-z0-9+/]+$/.test(body) && !/^[A-Za-z0-9_-]+$/.test(body)) return undefined;
	const remainder = body.length % 4;
	// No base64 encoding produces a body of length ≡ 1 (mod 4).
	if (remainder === 1) return undefined;
	// When padding is present it must bring the total to a multiple of 4.
	if (padding > 0 && remainder !== 4 - padding) return undefined;
	return Math.floor((body.length * 3) / 4);
}

/**
 * Estimates how many bytes of key material a configured secret carries.
 *
 * The answer is the SMALLEST plausible reading of the string, because that is
 * the one an attacker gets to use: `openssl rand -hex 16` produces a
 * 32-*character* value that is only 16 *bytes* of randomness, and a
 * 32-character base64 body is 24 bytes.
 *
 * That is also right for values never meant as an encoding. A 32-character
 * password drawn from `[A-Za-z0-9]` reads as base64 and scores 24 bytes, and it
 * genuinely carries only ~190 bits (~5.95 bits per character, not 8).
 *
 * It cannot see structure: a 40-character English sentence measures 40 bytes
 * and carries far less. This checks key *length*; it is no substitute for
 * generating the key randomly, which {@link describeWeakSecret} tells the
 * operator to do.
 */
export function measureSecretEntropyBytes(secret: string): number {
	const candidates = [
		Buffer.byteLength(secret, "utf8"),
		hexByteLength(secret),
		base64ByteLength(secret),
	].filter((length): length is number => length !== undefined);
	return Math.min(...candidates);
}

/**
 * Operator-facing explanation for a secret that misses the floor, naming the
 * field the way the config path does (`secret`, `previousSecrets[0].secret`).
 *
 * It takes the measurement and not the secret, which is the guarantee that the
 * rejected value cannot be echoed: this message is destined for stdout, a
 * container log, and quite possibly a pasted bug report.
 */
export function describeWeakSecret(field: string, actualBytes: number): string {
	return (
		`${field} must carry at least ${MIN_SECRET_ENTROPY_BYTES} bytes ` +
		`(${MIN_SECRET_ENTROPY_BYTES * 8} bits) of key material, but carries ${actualBytes} — ` +
		`generate one with \`openssl rand -hex ${MIN_SECRET_ENTROPY_BYTES}\`. Hex and base64 ` +
		`values are measured on their DECODED length, so a ${MIN_SECRET_ENTROPY_BYTES}-character ` +
		`hex string counts as only ${MIN_SECRET_ENTROPY_BYTES / 2} bytes.`
	);
}
