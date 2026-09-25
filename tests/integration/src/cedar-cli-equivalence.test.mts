// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The CLI-equivalence suite (#198, #284): for the same `.cedar` files and the
 * same request, `CedarPolicyRuleCollector` over each engine and the official
 * `cedar` CLI of that engine's Cedar must agree — on the decision, on the
 * policies that determined it, and on which policies raised evaluation errors.
 * It is the proof #185 called the migration criterion: that the entity
 * synthesis, the context allowlist and the answer interpretation here do not
 * drift from what Cedar computes, so a corpus can move to another Cedar
 * evaluator unchanged.
 *
 * Two engines, two Cedars:
 * - **wasm** evaluates in-process with `@cedar-policy/cedar-wasm`, held to the
 *   CLI of the version that package is pinned to (4.x).
 * - **http** hands the request to a real cedar-agent, which evaluates with the
 *   cedar-policy compiled into its image (2.5 in `permitio/cedar-agent:0.2.2`),
 *   held to the CLI of that version. A case whose file holds several policies
 *   is the wasm engine's only, and the http half says it skips it: cedar-agent
 *   stores one policy per id. `onNoDeterminingPolicy = "abstain"` is refused
 *   at boot over an out-of-process engine, so the http half runs such a case
 *   under `"deny"`: Cedar's answer does not depend on it, and the collector's
 *   reading of it under `"abstain"` is the wasm half's to check.
 *
 * Both engines are held to the same stated answers, so the corpus is also
 * measured across the two Cedars: a case that meant one thing under 4.x and
 * another under 2.5 fails on one side.
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
 * Policy ids. The engines name each policy for its file (`namePolicies`) and
 * ignore `@id`; the CLI names a policy by its `@id` annotation, else by its
 * position in the set. Every fixture policy carries `@id` with the id its file
 * gives it, so both answer in the same names, and a policy an engine named
 * differently is a mismatch. The agent holds each id under the load's mark
 * (#283); its error strings carry the mark, and it is set aside to compare.
 *
 * What each engine needs, and without it the engine's half is skipped with a
 * notice (its `…_REQUIRED=1` — set by the CI job that provides it — turns the
 * absence into a failure):
 * - wasm: the CLI as `CEDAR_CLI`, else `cedar` on the PATH, at the version
 *   `@cedar-policy/cedar-wasm` is pinned to. `CEDAR_CLI_REQUIRED`.
 * - http: an agent at `CEDAR_AGENT_ENDPOINT` (`CEDAR_AGENT_AUTHENTICATION` its
 *   token), the CLI of its Cedar as `CEDAR_AGENT_CLI`, and that version as
 *   `CEDAR_AGENT_CEDAR_VERSION` — read from the agent image by the CI job,
 *   since the agent does not say. `CEDAR_AGENT_REQUIRED`.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type CedarDecision,
	type CedarEngine,
	CedarPolicyRuleCollector,
	type CedarRequest,
	createCedarHttpEngine,
	entityUidLiteral,
	loadPolicySource,
	type NoDeterminingPolicy,
	type PolicySource,
	registerCedarEngine,
} from "@o3co/auth.policy-verifier.cedar";
import { cedarWasmEngine } from "@o3co/auth.policy-verifier.cedar-wasm";
import {
	type AnyRule,
	type CollectorContext,
	type EvaluatedRevision,
	evaluate,
	type Logger,
	type RuleEvaluation,
	type RuleOutcome,
} from "@o3co/auth.policy-verifier.core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	type CliAnswer,
	cedarAuthorize,
	cedarCliVersion,
	EVALUATION_ERROR,
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
	/** Whether each of its files holds one policy — one `@id` — as cedar-agent requires. */
	onePolicyPerFile: boolean;
}

const CASES: Case[] = readdirSync(FIXTURES, { withFileTypes: true })
	.filter((entry) => entry.isDirectory())
	.map((entry) => {
		const policies = join(FIXTURES, entry.name, "policies");
		const onePolicyPerFile = readdirSync(policies).every(
			(file) => (readFileSync(join(policies, file), "utf8").match(/@id\(/g) ?? []).length === 1,
		);
		return {
			name: entry.name,
			onePolicyPerFile,
			...(JSON.parse(readFileSync(join(FIXTURES, entry.name, "case.json"), "utf8")) as Omit<
				Case,
				"name" | "onePolicyPerFile"
			>),
		};
	})
	.sort((a, b) => a.name.localeCompare(b.name));

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

/** One engine, the CLI of its Cedar, and how its answers are read. */
interface Evaluator {
	/** The engine's config name; each case registers it observed, as `cli-equivalence-<name>-<case>`. */
	name: string;
	/** Absent: the engine's half is skipped, or fails when `requiredBy` is set to 1. */
	cli: string | undefined;
	/** The variable that turns a skip into a failure. */
	requiredBy: string;
	/** What is missing, for the notice. */
	needs: string;
	/** The Cedar version the engine runs, which its CLI must be. */
	cedarVersion: () => string;
	/** A fresh engine for one case — the http engine takes one agent per collector. */
	engine: () => CedarEngine;
	/** Collector config the engine reads (endpoint, token). */
	config: Record<string, unknown>;
	/** Why the engine cannot run a case, or `undefined` when it can. */
	cannotRun: (testCase: Case) => string | undefined;
	/** The case's mapping config, as the engine runs it. */
	configOf: (testCase: Case) => Case["config"];
	/** The engine's errors as `policyId: message`, in the file ids the CLI uses. */
	errors: (answer: CedarDecision) => string[];
	/** What a completed or failed evaluation reports of the revision. */
	revision: (source: PolicySource) => EvaluatedRevision;
}

const WASM: Evaluator = {
	name: "wasm",
	cli: locateCedarCli(),
	requiredBy: "CEDAR_CLI_REQUIRED",
	needs: "the cedar CLI (CEDAR_CLI, or `cedar` on the PATH)",
	cedarVersion: () => {
		const pinned = (
			JSON.parse(readFileSync(join(CEDAR_WASM, "package.json"), "utf8")) as {
				dependencies: Record<string, string>;
			}
		).dependencies["@cedar-policy/cedar-wasm"];
		const installed = versionAt(join(CEDAR_WASM, "node_modules/@cedar-policy/cedar-wasm"));
		if (installed !== pinned) {
			throw new Error(
				`@cedar-policy/cedar-wasm is pinned to ${pinned} and ${installed} is installed — run pnpm install`,
			);
		}
		return installed;
	},
	engine: () => cedarWasmEngine,
	config: {},
	cannotRun: () => undefined,
	configOf: (testCase) => testCase.config,
	// The wasm engine renders an error `policyId: message` already.
	errors: (answer) => [...answer.errors],
	revision: (source) => ({ revision: source.revision }),
};

const AGENT_ENDPOINT = process.env.CEDAR_AGENT_ENDPOINT;
const HTTP: Evaluator = {
	name: "http",
	cli: AGENT_ENDPOINT === undefined ? undefined : process.env.CEDAR_AGENT_CLI,
	requiredBy: "CEDAR_AGENT_REQUIRED",
	needs:
		"a cedar-agent (CEDAR_AGENT_ENDPOINT) and the CLI of its Cedar (CEDAR_AGENT_CLI, CEDAR_AGENT_CEDAR_VERSION)",
	cedarVersion: () => {
		const version = process.env.CEDAR_AGENT_CEDAR_VERSION;
		if (version === undefined || !/^\d+\.\d+\.\d+$/.test(version)) {
			throw new Error(
				"CEDAR_AGENT_CEDAR_VERSION must name the cedar-policy version the agent runs — the agent does not say",
			);
		}
		return version;
	},
	engine: () => createCedarHttpEngine(),
	config: {
		endpoint: AGENT_ENDPOINT,
		...(process.env.CEDAR_AGENT_AUTHENTICATION === undefined
			? {}
			: { authentication: process.env.CEDAR_AGENT_AUTHENTICATION }),
	},
	cannotRun: (testCase) =>
		testCase.onePolicyPerFile
			? undefined
			: "a file holds several policies, and cedar-agent stores one per id",
	// "abstain" is refused over an out-of-process engine; Cedar's answer does
	// not depend on it, so the case runs under "deny".
	configOf: (testCase) =>
		testCase.config.onNoDeterminingPolicy === "abstain"
			? { ...testCase.config, onNoDeterminingPolicy: "deny" }
			: testCase.config,
	// The agent's own strings, its ids under the load's mark (#283): read with
	// the CLI's parser, the mark set aside.
	errors: (answer) =>
		answer.errors.map((rendered) => {
			const error = EVALUATION_ERROR.exec(rendered);
			if (error === null) throw new Error(`an agent error this suite cannot read: ${rendered}`);
			return `${error[1].replace(/@[0-9a-f]{16}$/, "")}: ${error[2]}`;
		}),
	// The agent cannot vouch for what it ran (#244).
	revision: (source) => ({ revision: null, loadedRevision: source.revision }),
};

describe.each([WASM, HTTP])("the $name engine and the cedar CLI of its Cedar", (evaluator) => {
	const cli = evaluator.cli;
	const required = process.env[evaluator.requiredBy] === "1";

	// Skipped, not silent: said on stderr, where the default reporter does not
	// swallow it, and by a skipped test that says why, for a verbose reporter.
	if (cli === undefined && !required) {
		process.stderr.write(
			`cedar-cli-equivalence: the ${evaluator.name} engine's half is skipped — it needs ${evaluator.needs}\n`,
		);
	}
	describe.runIf(cli === undefined && !required)("not provided", () => {
		it.skip(`skips this engine's half — it needs ${evaluator.needs}`, () => {});
	});
	describe.runIf(cli === undefined && required)("required", () => {
		it("is provided — the CI job that requires it failed to", () => {
			expect.fail(
				`${evaluator.requiredBy}=1, and the ${evaluator.name} engine's half cannot run — it needs ${evaluator.needs}`,
			);
		});
	});

	describe.runIf(cli !== undefined)("agree", () => {
		const reference = cli as string;

		// Every comparison below is meaningless across two Cedar versions, so a
		// mismatch fails here, once, in words — not as a dozen answers that differ.
		beforeAll(() => {
			const [version, expected] = [cedarCliVersion(reference), evaluator.cedarVersion()];
			if (version !== expected) {
				throw new Error(
					`Cedar versions differ: the ${evaluator.name} engine runs ${expected}, the CLI at ${reference} is ${version} — install cedar-policy-cli ${expected}`,
				);
			}
		});

		it("run the same Cedar — the CLI is the version the engine runs", () => {
			expect(cedarCliVersion(reference)).toBe(evaluator.cedarVersion());
		});

		const runnable = CASES.filter((testCase) => evaluator.cannotRun(testCase) === undefined);

		it("cover the cases the engine can run", () => {
			expect(runnable.length).toBeGreaterThan(0);
			for (const testCase of runnable) expect(testCase.requests.length).toBeGreaterThan(0);
		});

		for (const testCase of CASES) {
			const why = evaluator.cannotRun(testCase);
			if (why !== undefined) it.skip(`${testCase.name}: not run — ${why}`, () => {});
		}

		describe.each(runnable)("$name", (testCase) => {
			const policyDir = join(FIXTURES, testCase.name, "policies");
			const source = loadPolicySource({ policyDir });
			const config = evaluator.configOf(testCase);
			// The engine, observed: every request the collector hands it and what it
			// answered, so the CLI is asked exactly what the engine was.
			const observed: Array<{ request: CedarRequest; answer: CedarDecision }> = [];
			// Registered per case, under its own name: the http engine holds one
			// agent per engine, and each case loads its own set into it.
			const engineName = `cli-equivalence-${evaluator.name}-${testCase.name}`;
			let rule: AnyRule;
			let scratch: string;

			beforeAll(async () => {
				const inner = evaluator.engine();
				registerCedarEngine({
					name: engineName,
					async: inner.async,
					confirmsRevision: inner.confirmsRevision,
					async load(loadSource, loadContext) {
						const loaded = await inner.load(loadSource, loadContext);
						return loaded.async
							? {
									async: true,
									async isAuthorized(request, signal) {
										const answer = await loaded.isAuthorized(request, signal);
										observed.push({ request, answer });
										return answer;
									},
								}
							: {
									async: false,
									isAuthorized(request) {
										const answer = loaded.isAuthorized(request);
										observed.push({ request, answer });
										return answer;
									},
								};
					},
				} as CedarEngine);
				const collector = await CedarPolicyRuleCollector.create(
					{ ...config, ...evaluator.config, policyDir, engine: engineName },
					{ logger: silent },
				);
				[rule] = await collector.collect(context);
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
				const cliAnswer: CliAnswer = cedarAuthorize(reference, files);

				// Cedar's answer, twice: the engine's and the CLI's are one answer.
				expect(answer).not.toHaveProperty("foreign");
				expect(answer.decision).toBe(cliAnswer.decision);
				expect([...answer.reason].sort()).toEqual([...cliAnswer.reason].sort());
				expect(evaluator.errors(answer).sort()).toEqual(
					cliAnswer.errors.map(({ policyId, message }) => `${policyId}: ${message}`).sort(),
				);

				// …and it is the answer the case states, so neither engine, nor either
				// Cedar, can drift alone — or both together.
				expect(cliAnswer.decision).toBe(request.expect.decision);
				expect([...cliAnswer.reason].sort()).toEqual(
					[...request.expect.determiningPolicies].sort(),
				);
				expect(cliAnswer.errors.map((error) => error.policyId).sort()).toEqual(
					[...request.expect.errorsIn].sort(),
				);

				// What the collector made of it: its answer table, over Cedar's answer.
				if (answer.errors.length > 0) {
					// An erroring policy stops deciding, so Cedar may allow on another
					// permit; the collector denies instead — the fail-open trap, closed.
					expect(outcome).toMatchObject({
						passed: false,
						evaluation: { status: "failed", ...evaluator.revision(source) },
					});
					return;
				}
				const abstains = (config.onNoDeterminingPolicy ?? "deny") === "abstain";
				expect(outcome.passed).toBe(
					answer.decision === "allow" || (answer.reason.length === 0 && abstains),
				);
				expect(outcome.evaluation).toEqual({
					status: "completed",
					...evaluator.revision(source),
					determiningPolicies: [...cliAnswer.reason].sort(),
				} as RuleEvaluation);
			});
		});
	});
});
