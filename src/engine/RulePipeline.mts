import type { Rule, RuleCollector, CollectorContext } from "./types.mjs";

export class RulePipeline {
	constructor(private collectors: RuleCollector[]) {}

	async collect(context: CollectorContext): Promise<Rule[]> {
		const results = await Promise.all(
			this.collectors.map((c) => c.collect(context)),
		);
		return results.flat();
	}
}
