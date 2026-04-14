export class Registry<T> {
	private readonly map = new Map<string, T>();

	register(name: string, instance: T): void {
		if (this.map.has(name)) {
			throw new Error(`Registry: "${name}" is already registered`);
		}
		this.map.set(name, instance);
	}

	get(name: string): T {
		if (!this.map.has(name)) {
			throw new Error(`Registry: "${name}" is not registered`);
		}
		return this.map.get(name) as T;
	}

	has(name: string): boolean {
		return this.map.has(name);
	}

	entries(): [string, T][] {
		return [...this.map.entries()];
	}
}
