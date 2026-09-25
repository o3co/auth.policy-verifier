// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The CLI-equivalence suite (#198): for the same `.cedar` files and the same
 * request, `CedarPolicyRuleCollector` over the wasm engine and the official
 * `cedar` CLI must agree — on the decision, on the policies that determined
 * it, and on which policies raised evaluation errors. It is the proof #185
 * called the migration criterion: that the entity synthesis, the context
 * allowlist and the answer interpretation here do not drift from what Cedar
 * computes, so a corpus can move to another Cedar evaluator unchanged.
 *
 * Each case under `conformance/fixtures/cedarCli/` holds `policies/*.cedar`
 * and a `case.json` of the collector's mapping config and the requests: the
 * attributes the collector sees, and what must come of them. Three things are
 * checked per request, and each catches what the others cannot:
 *
 * - The CLI is asked exactly the request the collector built — captured from
 *   the engine it passed it to — and must answer as the engine did. That
 *   measures Cedar's semantics and the policy naming, not the synthesis: both
 *   sides see the same request.
 * - So the synthesis is measured against the case: the request the collector
 *   built must be the one the case records (`expect.request`, principal to
 *   entities), and the answer the one it states. A change to how requests are
 *   built shows as a diff to review, whether or not it flips an answer.
 * - The collector's own reading of the answer: its answer table, over Cedar's.
 *
 * The recorded requests were generated from the collector and then read, one
 * by one. A diff in them after a change to the synthesis is for review, the
 * same way: regenerating them unread would make the check say nothing, while
 * the stated answers (`decision`, `determiningPolicies`, `errorsIn`) still
 * hold the meaning.
 *
 * Policy ids. The wasm engine names each policy for its file (`namePolicies`)
 * and ignores `@id`; the CLI names a policy by its `@id` annotation, else by
 * its position in the set. Every fixture policy carries `@id` with the id its
 * file gives it, so both answer in the same names, and a policy the engine
 * named differently is a mismatch.
 *
 * Only the wasm engine is measured. The `http` engine hands the request to a
 * cedar-agent that evaluates with cedar-policy 2.4, a different Cedar; checking
 * it against Cedar needs that CLI or a real agent, and is not this suite's.
 *
 * The CLI is found as `CEDAR_CLI`, else `cedar` on the PATH, and must be the
 * version `@cedar-policy/cedar-wasm` is pinned to. Without it the suite is
 * skipped with a notice; `CEDAR_CLI_REQUIRED=1` — set by the CI job that
 * installs it — turns a missing CLI into a failure.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type CedarDecision,
	CedarPolicyRuleCollector,
	type CedarRequest,
	entityUidLiteral,
	loadPolicySource,
	type NoDeterminingPolicy,
	registerCedarEngine,
} from "@o3co/auth.policy-verifier.cedar";
import { cedarWasmEngine } from "@o3co/auth.policy-verifier.cedar-wasm";
import {
	type CollectorContext,
	evaluate,
	isAsyncRule,
	type Logger,
	type Rule,
	type RuleOutcome,
} from "@o3co/auth.policy-verifier.core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	type CliAnswer,
	cedarAuthorize,
	cedarCliVersion,
	locateCedarCli,
} from "./conformance/cedarCli.mjs";

const FIXTURES = fileURLToPath(new URL("./conformance/fixtures/cedarCli/", import.meta.url));
const CEDAR_WASM = fileURLToPath(new URL("../../../packages/cedar-wasm/", import.meta.url));

interface CaseRequest {
	about: string;
	attributes: Record<string, unknown>;
	expect: {
		/** The request the collector must build from `attributes`. */
		request: CedarRequest;
		decision: "allow" | "deny";
		determiningPolicies: string[];
		/** The policies whose evaluation raised an error. */
		errorsIn: string[];
	};
}

interface Case {
	name: string;
	about: string;
	/** The collector's mapping config, without `policyDir` and `engine`. */
	config: Record<string, unknown> & { onNoDeterminingPolicy?: NoDeterminingPolicy };
	requests: CaseRequest[];
}

const CASES: Case[] = readdirSync(FIXTURES, { withFileTypes: true })
	.filter((entry) => entry.isDirectory())
	.map((entry) => ({
		name: entry.name,
		...(JSON.parse(readFileSync(join(FIXTURES, entry.name, "case.json"), "utf8")) as Omit<
			Case,
			"name"
		>),
	}))
	.sort((a, b) => a.name.localeCompare(b.name));

/*
 * The wasm engine, observed: every request the collector hands it and what it
 * answered, so the CLI is asked exactly what the engine was. Registered once,
 * at module scope, under a fixed name — which assumes the file is evaluated
 * once per global, as vitest's default isolation does; `--no-isolate` would
 * register it twice and be refused. The tests run one at a time, so the one
 * `observed` list is theirs in turn.
 */
const OBSERVED_ENGINE = "cli-equivalence-wasm";
const observed: Array<{ request: CedarRequest; answer: CedarDecision }> = [];
registerCedarEngine({
	name: OBSERVED_ENGINE,
	async: false,
	confirmsRevision: true,
	load(source) {
		const loaded = cedarWasmEngine.load(source);
		return {
			async: false,
			isAuthorized(request: CedarRequest): CedarDecision {
				const answer = loaded.isAuthorized(request);
				observed.push({ request, answer });
				return answer;
			},
		};
	},
});

/** Never read: everything reaches the rule through its attributes. */
const context: CollectorContext = {
	subject: { sub: "alice" },
	resource: { raw: "document:42", resourceType: "document", resourceId: "42" },
	action: "read",
	signal: new AbortController().signal,
};

/** Evaluation errors are this suite's to compare, not to print. */
const silent: Logger = {
	trace: () => {},
	debug: () => {},
	info: () => {},
	warn: () => {},
	error: () => {},
	fatal: () => {},
	child: () => silent,
};

/** A package's own version, read from its `package.json`. */
function versionAt(dir: string): string {
	return (JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { version: string })
		.version;
}

const CLI = locateCedarCli();
const REQUIRED = process.env.CEDAR_CLI_REQUIRED === "1";

// Skipped, not silent: said on stderr, where the default reporter does not
// swallow it, and by a skipped test that says why, for a verbose reporter.
if (CLI === undefined && !REQUIRED) {
	process.stderr.write(
		"cedar-cli-equivalence: no cedar CLI found (CEDAR_CLI, or `cedar` on the PATH) — the suite is skipped\n",
	);
}
describe.runIf(CLI === undefined && !REQUIRED)("the cedar CLI, not found", () => {
	it.skip("skips the CLI-equivalence suite — install cedar-policy-cli at the version @cedar-policy/cedar-wasm is pinned to, on the PATH or as CEDAR_CLI, to run it", () => {});
});

describe.runIf(CLI === undefined && REQUIRED)("the cedar CLI, required", () => {
	it("is installed — CEDAR_CLI_REQUIRED is set, so a missing CLI fails rather than skips", () => {
		expect.fail(
			"CEDAR_CLI_REQUIRED=1 but no cedar CLI was found (CEDAR_CLI, or `cedar` on the PATH)",
		);
	});
});

describe.runIf(CLI !== undefined)("CedarPolicyRuleCollector and the cedar CLI agree (#198)", () => {
	const cli = CLI as string;
	// Read when the suite runs, not when it is collected: a skipped suite must
	// load wherever the package is laid out.
	const pinned = () =>
		(
			JSON.parse(readFileSync(join(CEDAR_WASM, "package.json"), "utf8")) as {
				dependencies: Record<string, string>;
			}
		).dependencies["@cedar-policy/cedar-wasm"];
	const installed = () => versionAt(join(CEDAR_WASM, "node_modules/@cedar-policy/cedar-wasm"));

	// Every comparison below is meaningless across two Cedar versions, so a
	// mismatch fails here, once, in words — not as a dozen answers that differ.
	beforeAll(() => {
		const [version, wasm, pin] = [cedarCliVersion(cli), installed(), pinned()];
		if (version !== wasm || wasm !== pin) {
			throw new Error(
				`Cedar versions differ: the cedar CLI at ${cli} is ${version}, @cedar-policy/cedar-wasm is pinned to ${pin} and ${wasm} is installed — run pnpm install, and install cedar-policy-cli ${pin}`,
			);
		}
	});

	it("run the same Cedar — the CLI is the version the wasm engine is pinned to and runs", () => {
		expect(installed()).toBe(pinned());
		expect(cedarCliVersion(cli)).toBe(installed());
	});

	it("cover every case the fixtures hold", () => {
		expect(CASES.length).toBeGreaterThan(0);
		for (const testCase of CASES) expect(testCase.requests.length).toBeGreaterThan(0);
	});

	describe.each(CASES)("$name", (testCase) => {
		const policyDir = join(FIXTURES, testCase.name, "policies");
		const source = loadPolicySource({ policyDir });
		let rule: Rule;
		let scratch: string;

		beforeAll(async () => {
			const collector = await CedarPolicyRuleCollector.create(
				{ ...testCase.config, policyDir, engine: OBSERVED_ENGINE },
				{ logger: silent },
			);
			const [collected] = await collector.collect(context);
			if (isAsyncRule(collected)) throw new Error("the wasm engine answers synchronously");
			rule = collected;
			scratch = mkdtempSync(join(tmpdir(), "cedar-cli-equivalence-"));
			writeFileSync(join(scratch, "policies.cedar"), source.text);
		});

		afterAll(() => {
			if (scratch !== undefined) rmSync(scratch, { recursive: true, force: true });
		});

		it.each(testCase.requests)("$about", async (request) => {
			observed.length = 0;
			const decision = await evaluate(new Map(Object.entries(request.attributes)), [rule]);
			const outcome: RuleOutcome = decision.reason.groups[0].evaluated[0];
			expect(observed).toHaveLength(1);
			const [{ request: asked, answer }] = observed;

			// The synthesis, against the case: the request the collector built.
			expect(asked).toEqual(request.expect.request);

			// The CLI is asked what the engine was asked.
			const files = {
				policies: join(scratch, "policies.cedar"),
				entities: join(scratch, "entities.json"),
				request: join(scratch, "request.json"),
			};
			writeFileSync(files.entities, JSON.stringify(asked.entities));
			writeFileSync(
				files.request,
				JSON.stringify({
					principal: entityUidLiteral(asked.principal),
					action: entityUidLiteral(asked.action),
					resource: entityUidLiteral(asked.resource),
					context: asked.context,
				}),
			);
			const reference: CliAnswer = cedarAuthorize(cli, files);

			// Cedar's answer, twice: the engine's and the CLI's are one answer. The
			// wasm engine renders an error `policyId: message`; so is the CLI's here.
			expect(answer.decision).toBe(reference.decision);
			expect([...answer.reason].sort()).toEqual([...reference.reason].sort());
			expect([...answer.errors].sort()).toEqual(
				reference.errors.map(({ policyId, message }) => `${policyId}: ${message}`).sort(),
			);

			// …and it is the answer the case states, so both cannot drift together.
			expect(reference.decision).toBe(request.expect.decision);
			expect([...reference.reason].sort()).toEqual([...request.expect.determiningPolicies].sort());
			expect(reference.errors.map((error) => error.policyId).sort()).toEqual(
				[...request.expect.errorsIn].sort(),
			);

			// What the collector made of it: its answer table, over Cedar's answer.
			if (answer.errors.length > 0) {
				// An erroring policy stops deciding, so Cedar may allow on another
				// permit; the collector denies instead — the fail-open trap, closed.
				expect(outcome).toMatchObject({
					passed: false,
					evaluation: { status: "failed", revision: source.revision },
				});
				return;
			}
			const abstains = (testCase.config.onNoDeterminingPolicy ?? "deny") === "abstain";
			expect(outcome.passed).toBe(
				answer.decision === "allow" || (answer.reason.length === 0 && abstains),
			);
			expect(outcome.evaluation).toEqual({
				status: "completed",
				revision: source.revision,
				determiningPolicies: [...reference.reason].sort(),
			});
		});
	});
});
