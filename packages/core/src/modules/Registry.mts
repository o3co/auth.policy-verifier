// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Name-keyed registry of instances. Duplicate registrations and missing lookups
 * throw — callers can treat registered names as always present after `register`.
 */
export class Registry<T> {
	private readonly map = new Map<string, T>();

	/** Registers `instance` under `name`. Throws if `name` is already registered. */
	register(name: string, instance: T): void {
		if (this.map.has(name)) {
			throw new Error(`Registry: "${name}" is already registered`);
		}
		this.map.set(name, instance);
	}

	/** Returns the instance registered under `name`. Throws if not registered. */
	get(name: string): T {
		if (!this.map.has(name)) {
			throw new Error(`Registry: "${name}" is not registered`);
		}
		return this.map.get(name) as T;
	}

	/** Returns `true` if an instance is registered under `name`. */
	has(name: string): boolean {
		return this.map.has(name);
	}

	/** Returns a snapshot of all `[name, instance]` pairs. */
	entries(): [string, T][] {
		return [...this.map.entries()];
	}
}
