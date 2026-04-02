import type { AttributeCollector, Attributes, CollectorContext } from "./types.mjs";

export class AttributePipeline {
	constructor(private collectors: AttributeCollector[]) {}

	async collect(context: CollectorContext): Promise<Attributes> {
		const results = await Promise.all(this.collectors.map((c) => c.collect(context)));
		return merge(results);
	}
}

function merge(maps: Attributes[]): Attributes {
	const merged: Attributes = new Map();
	for (const map of maps) {
		for (const [key, value] of map) {
			const existing = merged.get(key);
			if (Array.isArray(existing) && Array.isArray(value)) {
				merged.set(key, [...existing, ...value]);
			} else {
				merged.set(key, value);
			}
		}
	}
	return merged;
}
