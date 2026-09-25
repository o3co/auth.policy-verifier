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
 *   held to the CLI of that version.
 *
 * Every case is measured under both Cedars, since what a case means is its
 * CLIs' answer, not an engine's: each half holds its CLI to the case's stated
 * answers, so a case that meant one thing under 4.x and another under 2.5
 * fails on one side. What an engine cannot load is declared, and the
 * declaration is checked:
 * - A case whose set cedar-agent refuses states why (`agentRefuses` — a file
 *   holding several policies, where the agent stores one per id). The http
 *   half checks that the agent does refuse it at boot, and still holds the
 *   CLI of the agent's Cedar to the case's answers, asked the recorded
 *   requests. A case that stops being refused fails, as does one that starts.
 * - `onNoDeterminingPolicy = "abstain"` is refused at boot over an
 *   out-of-process engine, so the http half runs such a case under `"deny"`
 *   and says so in its name: Cedar's answer does not depend on it, and the
 *   collector's reading of it under `"abstain"` is the wasm half's to check.
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
 * (#283), and its error strings carry it: this load's mark is set aside to
 * compare, and an error naming a policy under any other mark is a mismatch.
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
	agentPolicyId,
	type CedarDecision,
	type CedarEngine,
	CedarPolicyRuleCollector,
	type CedarRequest,
	createCedarHttpEngine,
	entityUidLiteral,
	type LoadedCedarPolicySet,
	loadPolicySource,
	type NoDeterminingPolicy,
	namePolicies,
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
	/** Why cedar-agent refuses this case's set at boot, when it does. */
	agentRefuses?: string;
	/** The collector's mapping config, without `policyDir` and `engine`. */
	config: Record<string, unknown> & { onNoDeterminingPolicy?: NoDeterminingPolicy };
	requests: CaseRequest[];
}

const CASES: Case[] = readdirSync(FIXTURES, { withFileTypes: true })
	.filter((entry) => entry.isDirectory())
	.map((entry) => {
		const testCase: Case = {
			name: entry.name,
			...(JSON.parse(readFileSync(join(FIXTURES, entry.name, "case.json"), "utf8")) as Omit<
				Case,
				"name"
			>),
		};
		// A reason, or nothing: a refusal is stated, never a flag.
		const refuses: unknown = testCase.agentRefuses;
		if (refuses !== undefined && (typeof refuses !== "string" || refuses.trim() === "")) {
			throw new Error(`${entry.name}/case.json: agentRefuses must say why, as text`);
		}
		return testCase;
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

/** The case's mapping config as an engine runs it, and what was changed to run it. */
interface RunConfig {
	config: Case["config"];
	/** Said in the case's test name, so a changed config is never silent. */
	changed?: string;
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
	/**
	 * The engine a case loads its set into. The http engine holds one agent per
	 * engine, so each case gets its own; the wasm engine has no state to keep
	 * apart and is shared.
	 */
	engine: () => CedarEngine;
	/** Collector config the engine reads (endpoint, token). */
	config: Record<string, unknown>;
	/** Why the engine refuses a case's set at boot, or `undefined` when it loads it. */
	refuses: (testCase: Case) => string | undefined;
	runConfig: (testCase: Case) => RunConfig;
	/** The engine's errors as `policyId: message`, in the file ids the CLI uses. */
	errors: (answer: CedarDecision, source: PolicySource) => string[];
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
	refuses: () => undefined,
	runConfig: (testCase) => ({ config: testCase.config }),
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
	// Under vitest's 10 s hook timeout, so an agent that does not answer fails
	// with the engine's own words rather than a bare "hook timed out".
	engine: () => createCedarHttpEngine({ loadTimeoutMs: 5_000 }),
	config: {
		endpoint: AGENT_ENDPOINT,
		...(process.env.CEDAR_AGENT_AUTHENTICATION === undefined
			? {}
			: { authentication: process.env.CEDAR_AGENT_AUTHENTICATION }),
	},
	refuses: (testCase) => testCase.agentRefuses,
	// "abstain" is refused over an out-of-process engine; Cedar's answer does
	// not depend on it, so the case runs under "deny".
	runConfig: (testCase) =>
		testCase.config.onNoDeterminingPolicy === "abstain"
			? {
					config: { ...testCase.config, onNoDeterminingPolicy: "deny" },
					changed: 'run under onNoDeterminingPolicy = "deny"',
				}
			: { config: testCase.config },
	// The agent's own strings, each policy id under the load's mark (#283): read
	// with the CLI's parser, and only this load's mark set aside — an id under
	// another stays as it is, and fails to match.
	errors: (answer, source) =>
		answer.errors.map((rendered) => {
			const error = EVALUATION_ERROR.exec(rendered);
			if (error === null) throw new Error(`an agent error this suite cannot read: ${rendered}`);
			const [, id, message] = error;
			const at = id.lastIndexOf("@");
			const stem = at === -1 ? id : id.slice(0, at);
			return `${agentPolicyId(stem, source.revision) === id ? stem : id}: ${message}`;
		}),
	// The agent cannot vouch for what it ran (#244).
	revision: (source) => ({ revision: null, loadedRevision: source.revision }),
};

/**
 * `inner`, registered under `name` with every request it is asked and its
 * answer pushed to `observed` — so the CLI is asked exactly what it was.
 */
function registerObserved(
	name: string,
	inner: CedarEngine,
	observed: Array<{ request: CedarRequest; answer: CedarDecision }>,
): void {
	registerCedarEngine({
		name,
		async: inner.async,
		confirmsRevision: inner.confirmsRevision,
		async load(source, loadContext): Promise<LoadedCedarPolicySet> {
			const loaded = await inner.load(source, loadContext);
			if (loaded.async) {
				return {
					async: true,
					async isAuthorized(request, signal) {
						const answer = await loaded.isAuthorized(request, signal);
						observed.push({ request, answer });
						return answer;
					},
				};
			}
			return {
				async: false,
				isAuthorized(request) {
					const answer = loaded.isAuthorized(request);
					observed.push({ request, answer });
					return answer;
				},
			};
		},
	});
}

/** Asks the CLI at `cli` the request, over the set in `scratch/policies.cedar`. */
function askCli(cli: string, scratch: string, request: CedarRequest): CliAnswer {
	const files = {
		policies: join(scratch, "policies.cedar"),
		entities: join(scratch, "entities.json"),
		request: join(scratch, "request.json"),
	};
	writeFileSync(files.entities, JSON.stringify(request.entities));
	writeFileSync(
		files.request,
		JSON.stringify({
			principal: entityUidLiteral(request.principal),
			action: entityUidLiteral(request.action),
			resource: entityUidLiteral(request.resource),
			context: request.context,
		}),
	);
	return cedarAuthorize(cli, files);
}

/** The CLI's answer is the one the case states: what the case means, under this Cedar. */
function expectStated(cliAnswer: CliAnswer, stated: CaseRequest["expect"]): void {
	expect(cliAnswer.decision).toBe(stated.decision);
	expect([...cliAnswer.reason].sort()).toEqual([...stated.determiningPolicies].sort());
	expect(cliAnswer.errors.map((error) => error.policyId).sort()).toEqual(
		[...stated.errorsIn].sort(),
	);
}

// Outside the halves, so it runs once and on every machine — a CLI or not.
it("the fixtures hold cases, each with requests", () => {
	expect(CASES.length).toBeGreaterThan(0);
	for (const testCase of CASES) expect(testCase.requests.length).toBeGreaterThan(0);
});

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

		for (const testCase of CASES) {
			const policyDir = join(FIXTURES, testCase.name, "policies");
			const source = loadPolicySource({ policyDir });
			const refused = evaluator.refuses(testCase);
			const { config, changed } = evaluator.runConfig(testCase);
			// The engine, observed: every request the collector hands it and what it
			// answered, so the CLI is asked exactly what the engine was.
			const observed: Array<{ request: CedarRequest; answer: CedarDecision }> = [];
			// Registered per case, under its own name: the http engine holds one
			// agent per engine, and each case loads its own set into it.
			const engineName = `cli-equivalence-${evaluator.name}-${testCase.name}`;
			const create = () =>
				CedarPolicyRuleCollector.create(
					{ ...config, ...evaluator.config, policyDir, engine: engineName },
					{ logger: silent },
				);
			let rule: AnyRule;
			let refusal: unknown;
			let scratch: string;

			const title =
				refused !== undefined
					? `${testCase.name} — refused by the engine: ${refused}`
					: changed !== undefined
						? `${testCase.name} — ${changed}`
						: testCase.name;

			describe(title, () => {
				beforeAll(async () => {
					registerObserved(engineName, evaluator.engine(), observed);
					scratch = mkdtempSync(join(tmpdir(), "cedar-cli-equivalence-"));
					writeFileSync(join(scratch, "policies.cedar"), source.text);
					// Both under the hook timeout, which the engine's load deadline sits
					// under: an agent that does not answer fails in the engine's words.
					if (refused === undefined) [rule] = await create().then((c) => c.collect(context));
					else
						refusal = await create().then(
							() => undefined,
							(error: unknown) => error,
						);
				});

				afterAll(() => {
					if (scratch !== undefined) rmSync(scratch, { recursive: true, force: true });
				});

				if (refused !== undefined) {
					// The declaration, checked against the engine: the agent refuses the
					// set this load sent as one it cannot parse (400) — not a route, a
					// size or a fault — at boot, as the engine's docs say, not served.
					it("is refused at boot", () => {
						const sent = namePolicies(
							source.files.filter((file) => file.text.trim().length > 0),
							(file) => [file.text],
						)
							.map(({ id }) => agentPolicyId(id, source.revision))
							.join(", ");
						expect(refusal).toBeInstanceOf(Error);
						expect((refusal as Error).message).toContain(
							`refused the policy set from ${source.description} (400; policies: ${sent}): `,
						);
					});

					// What the case means under this Cedar, without the engine: the CLI
					// is asked the recorded request, which the wasm half checks is the
					// one the collector builds.
					it.each(testCase.requests)("$about — the CLI alone", (request) => {
						expectStated(askCli(reference, scratch, request.expect.request), request.expect);
					});
					return;
				}

				it.each(testCase.requests)("$about", async (request) => {
					observed.length = 0;
					const decision = await evaluate(new Map(Object.entries(request.attributes)), [rule]);
					const outcome: RuleOutcome = decision.reason.groups[0].evaluated[0];
					expect(observed).toHaveLength(1);
					const [{ request: asked, answer }] = observed;

					// The synthesis, against the case: the request the collector built.
					expect(asked).toEqual(request.expect.request);

					// The CLI is asked what the engine was asked.
					const cliAnswer = askCli(reference, scratch, asked);

					// Cedar's answer, twice: the engine's and the CLI's are one answer.
					expect(answer).not.toHaveProperty("foreign");
					expect(answer.decision).toBe(cliAnswer.decision);
					expect([...answer.reason].sort()).toEqual([...cliAnswer.reason].sort());
					expect(evaluator.errors(answer, source).sort()).toEqual(
						cliAnswer.errors.map(({ policyId, message }) => `${policyId}: ${message}`).sort(),
					);

					// …and it is the answer the case states, so neither engine, nor either
					// Cedar, can drift alone — or both together.
					expectStated(cliAnswer, request.expect);

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
		}
	});
});
