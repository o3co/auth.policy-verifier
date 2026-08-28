// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The parity test the one documented departure owes (#164).
 *
 * AGENTS.md, "Two-Boundary Config Validation": the invariant is that the same
 * configuration gets the same verdict at both boundaries. The mechanism is
 * normally one shared check function, which guarantees that structurally.
 * `assertVerifyRouterJwtConfig` and `AppConfigSchema`'s `superRefine` are the
 * section's one legitimate departure — #134 split the spellings, so the wire
 * says `oauth.jwt.mode = "insecure-decode"` (one key) where the internal config
 * says `validate: false` + `allowInsecureDecode: true` (two keys), and there is
 * no single shape for a shared function to read.
 *
 * The burden a departure carries is this file. Both sides already had parallel
 * suites pinning the same cases, but nothing asserted the two *agree* on one
 * input — which is what "held in step by hand" turned out to mean for the
 * numeric knobs in #157, where seven values had quietly diverged.
 *
 * Each row is one configuration written twice — once as an operator writes it
 * in a config file, once as a library consumer hands it to the router — and the
 * assertion is on the verdicts, not on how they are produced. A new invariant
 * on either side is a row here, not a new test.
 *
 * The table earned its keep on its first run: `tokenType: ["at+jwt"]` was
 * refused by the schema and accepted by the guard, whose `isPresent` was shared
 * with `issuer`/`audience` and so admitted a list for a header that is a single
 * value. See the `tokenType`-shaped rows below and the #164 CHANGELOG entry.
 */
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { assertVerifyRouterJwtConfig, type UncheckedJwtConfig } from "#/jwt/tokenAuthenticator.mjs";

/** 64 hex characters — clears the #114 entropy floor, so no row fails on its secret. */
const SECRET = "11".repeat(32);

/** Everything outside `oauth.jwt`, so only the block under test can decide a verdict. */
const REST_OF_CONFIG = {
	attribute: { collectors: [] },
	rule: { collectors: [] },
};

const ISSUER = "https://issuer.test";
const OTHER_ISSUER = "https://issuer-b.test";
const AUDIENCE = "https://api.test";
const TOKEN_TYPE = "at+jwt";

/** A complete verifying `oauth.jwt` block, in the wire spelling #134 settled on. */
const WIRE_VERIFYING = {
	algorithm: "HS256",
	secret: SECRET,
	mode: "verify",
	issuer: ISSUER,
	audience: AUDIENCE,
	tokenType: TOKEN_TYPE,
};

/** The same configuration as the router's internal discriminated union spells it. */
const GUARD_VERIFYING: UncheckedJwtConfig = {
	validate: true,
	issuer: ISSUER,
	audience: AUDIENCE,
	tokenType: TOKEN_TYPE,
};

/**
 * The boundary identity `createApp` passes, so a refusal names the `oauth.jwt.*`
 * key the operator actually wrote and the two sides can be compared at all.
 */
const AS_CREATE_APP = {
	caller: "createApp",
	path: "oauth.jwt",
	verifyCondition: 'oauth.jwt.mode is "verify"',
};

/**
 * A boundary's answer about one configuration. `key` is the key the refusal is
 * *about* — the one an operator is sent to go and look at — as distinct from
 * any further key the message mentions as the remedy.
 */
interface Verdict {
	accepted: boolean;
	key: string | null;
}

/** The config-file boundary: parse the block through `AppConfigSchema`. */
function schemaVerdict(jwt: Record<string, unknown>): Verdict {
	const result = AppConfigSchema.safeParse({ oauth: { jwt }, ...REST_OF_CONFIG });
	if (result.success) {
		return { accepted: true, key: null };
	}
	const first = result.error.issues.find(
		(issue) => issue.path[0] === "oauth" && issue.path[1] === "jwt" && issue.path.length > 2,
	);
	return { accepted: false, key: first ? String(first.path[2]) : "(block)" };
}

/**
 * The hand-built-config boundary: the guard `createApp` and `createVerifyRouter`
 * run. The subject key is the one the message opens with; the decode-only
 * refusal also names `allowInsecureDecode` further along, as the remedy rather
 * than as the thing that is wrong.
 */
function guardVerdict(jwt: UncheckedJwtConfig): Verdict {
	try {
		assertVerifyRouterJwtConfig(jwt, AS_CREATE_APP);
		return { accepted: true, key: null };
	} catch (cause) {
		const message = cause instanceof Error ? cause.message : String(cause);
		const subject = /^createApp: oauth\.jwt\.([A-Za-z][A-Za-z0-9]*)/.exec(message);
		return { accepted: false, key: subject ? (subject[1] as string) : "(unnamed)" };
	}
}

/**
 * What the two boundaries must answer. `asymmetry` exists for exactly one row —
 * the `tokenType` default carved out in AGENTS.md — so the departure is pinned
 * rather than skipped: closing it either way fails this table and sends the
 * author to the reasoning.
 */
type Expectation =
	| { both: "accept" }
	| { both: "refuse"; key: string }
	| { asymmetry: "documented"; schema: "accepts"; guard: "refuses"; key: string; why: string };

interface ParityCase {
	/** What the configuration is, phrased so a failure reads as a sentence. */
	name: string;
	/** The `oauth.jwt` block a config file carries. */
	wire: Record<string, unknown>;
	/** The same configuration handed straight to the router. */
	guard: UncheckedJwtConfig;
	expect: Expectation;
}

const PARITY_CASES: ParityCase[] = [
	{
		name: "a complete verifying config",
		wire: { ...WIRE_VERIFYING },
		guard: { ...GUARD_VERIFYING },
		expect: { both: "accept" },
	},
	{
		name: "a verifying config with array-valued issuer and audience",
		wire: { ...WIRE_VERIFYING, issuer: [ISSUER, OTHER_ISSUER], audience: [AUDIENCE] },
		guard: { ...GUARD_VERIFYING, issuer: [ISSUER, OTHER_ISSUER], audience: [AUDIENCE] },
		expect: { both: "accept" },
	},
	{
		name: "a verifying config with no issuer",
		wire: { ...WIRE_VERIFYING, issuer: undefined },
		guard: { ...GUARD_VERIFYING, issuer: undefined },
		expect: { both: "refuse", key: "issuer" },
	},
	{
		name: "a verifying config whose issuer is an empty string",
		wire: { ...WIRE_VERIFYING, issuer: "" },
		guard: { ...GUARD_VERIFYING, issuer: "" },
		expect: { both: "refuse", key: "issuer" },
	},
	{
		// The exact drift the pre-#132 `createApp` copy had: a bare falsy check
		// accepts `[]`, because an empty array is truthy.
		name: "a verifying config whose issuer is an empty array",
		wire: { ...WIRE_VERIFYING, issuer: [] },
		guard: { ...GUARD_VERIFYING, issuer: [] },
		expect: { both: "refuse", key: "issuer" },
	},
	{
		name: 'a verifying config whose issuer is [""]',
		wire: { ...WIRE_VERIFYING, issuer: [""] },
		guard: { ...GUARD_VERIFYING, issuer: [""] },
		expect: { both: "refuse", key: "issuer" },
	},
	{
		name: "a verifying config whose issuer array carries one empty entry",
		wire: { ...WIRE_VERIFYING, issuer: [ISSUER, ""] },
		guard: { ...GUARD_VERIFYING, issuer: [ISSUER, ""] },
		expect: { both: "refuse", key: "issuer" },
	},
	{
		// A HOCON env substitution delivers whatever the variable held, and a
		// JavaScript caller is not held to the declared type either.
		name: "a verifying config whose issuer is not a string",
		wire: { ...WIRE_VERIFYING, issuer: 42 },
		guard: { ...GUARD_VERIFYING, issuer: 42 as unknown as string },
		expect: { both: "refuse", key: "issuer" },
	},
	{
		name: "a verifying config with no audience",
		wire: { ...WIRE_VERIFYING, audience: undefined },
		guard: { ...GUARD_VERIFYING, audience: undefined },
		expect: { both: "refuse", key: "audience" },
	},
	{
		name: "a verifying config whose audience is an empty array",
		wire: { ...WIRE_VERIFYING, audience: [] },
		guard: { ...GUARD_VERIFYING, audience: [] },
		expect: { both: "refuse", key: "audience" },
	},
	{
		name: 'a verifying config whose audience is [""]',
		wire: { ...WIRE_VERIFYING, audience: [""] },
		guard: { ...GUARD_VERIFYING, audience: [""] },
		expect: { both: "refuse", key: "audience" },
	},
	{
		name: "a verifying config whose tokenType is an empty string",
		wire: { ...WIRE_VERIFYING, tokenType: "" },
		guard: { ...GUARD_VERIFYING, tokenType: "" },
		expect: { both: "refuse", key: "tokenType" },
	},
	{
		name: "a verifying config whose tokenType is not a string",
		wire: { ...WIRE_VERIFYING, tokenType: 42 },
		guard: { ...GUARD_VERIFYING, tokenType: 42 as unknown as string },
		expect: { both: "refuse", key: "tokenType" },
	},
	{
		// The divergence this table found (#164). `tokenType` is the accepted
		// `typ` header — one value, `z.string()` at the schema — where `issuer`
		// and `audience` may be lists because jose accepts lists for them. The
		// guard checked all three with the same list-tolerant `isPresent`, so
		// this booted and then rejected every token.
		name: "a verifying config whose tokenType is a one-element array",
		wire: { ...WIRE_VERIFYING, tokenType: [TOKEN_TYPE] },
		guard: { ...GUARD_VERIFYING, tokenType: [TOKEN_TYPE] as unknown as string },
		expect: { both: "refuse", key: "tokenType" },
	},
	{
		name: "a verifying config whose tokenType is an empty array",
		wire: { ...WIRE_VERIFYING, tokenType: [] },
		guard: { ...GUARD_VERIFYING, tokenType: [] as unknown as string },
		expect: { both: "refuse", key: "tokenType" },
	},
	{
		name: "a verifying config with no tokenType",
		wire: { ...WIRE_VERIFYING, tokenType: undefined },
		guard: { ...GUARD_VERIFYING, tokenType: undefined },
		expect: {
			asymmetry: "documented",
			schema: "accepts",
			guard: "refuses",
			key: "tokenType",
			why:
				"The schema defaults tokenType to at+jwt; the guard requires it. Deliberate, " +
				"and the only carve-out in AGENTS.md, Two-Boundary Config Validation: " +
				"VerifyingJwtConfig declares tokenType required, so the API boundary's static " +
				"contract already asks the caller for it and the guard is catching a JavaScript " +
				"caller who ignored it. Both boundaries still end with a verifying config that " +
				"pins typ; they differ on who supplies it, and the side without the default is " +
				"the fail-closed one.",
		},
	},
	{
		// The consent, in each spelling: one wire key, two internal ones (#134).
		name: "a decode-only config with the acknowledgment",
		wire: { algorithm: "HS256", mode: "insecure-decode" },
		guard: { validate: false, allowInsecureDecode: true },
		expect: { both: "accept" },
	},
	{
		// Decode-only reaches neither side's RFC 9068 presence checks, so an
		// issuer that would sink a verifying config is accepted by both.
		name: "a decode-only config that also carries an empty issuer",
		wire: { algorithm: "HS256", mode: "insecure-decode", issuer: [] },
		guard: { validate: false, allowInsecureDecode: true, issuer: [] },
		expect: { both: "accept" },
	},
	{
		// There is no wire spelling for decode-only *without* consent — the mode
		// string is the consent. The nearest thing an operator can write is the
		// key #134 removed, and the schema refuses that too, naming the key the
		// guard names. Both boundaries agree this configuration is unreachable.
		name: "a decode-only config without the acknowledgment",
		wire: { algorithm: "HS256", validate: false },
		guard: { validate: false },
		expect: { both: "refuse", key: "validate" },
	},
];

describe("Two-boundary parity — AppConfigSchema vs assertVerifyRouterJwtConfig (#164)", () => {
	it.each(PARITY_CASES)("$name", (parityCase) => {
		const schema = schemaVerdict(parityCase.wire);
		const guard = guardVerdict(parityCase.guard);

		if ("asymmetry" in parityCase.expect) {
			// Pinned, not skipped: the carve-out is asserted in the shape AGENTS.md
			// documents, so closing it in either direction fails here.
			expect(schema.accepted).toBe(true);
			expect(guard.accepted).toBe(false);
			expect(guard.key).toBe(parityCase.expect.key);
			return;
		}
		expect(schema.accepted).toBe(parityCase.expect.both === "accept");
		expect(guard.accepted).toBe(schema.accepted);
		if (parityCase.expect.both === "refuse") {
			expect(schema.key).toBe(parityCase.expect.key);
			expect(guard.key).toBe(parityCase.expect.key);
		}
	});

	it("has exactly one documented asymmetry, and it is the tokenType default", () => {
		// A second one would mean the departure had drifted again without the
		// reasoning in AGENTS.md having been revisited.
		const asymmetries = PARITY_CASES.filter((row) => "asymmetry" in row.expect);
		expect(asymmetries.map((row) => row.name)).toEqual(["a verifying config with no tokenType"]);
	});

	it("does not mistake the removed wire keys for the internal interlock", () => {
		// The trap #134's split leaves behind: `{ validate: false,
		// allowInsecureDecode: true }` is the *current* internal consent and the
		// *removed* wire spelling, so the identical text is accepted by the guard
		// and refused by the schema. That is the spelling split itself, not a
		// divergence — the wire counterpart of this internal config is
		// `mode: "insecure-decode"`, which is a row above. Pinned here so it is
		// not "fixed" into a parity row by someone reading the two as one config.
		const wire = { algorithm: "HS256", validate: false, allowInsecureDecode: true };
		expect(schemaVerdict(wire)).toMatchObject({ accepted: false, key: "validate" });
		expect(guardVerdict({ validate: false, allowInsecureDecode: true })).toMatchObject({
			accepted: true,
		});
	});
});
