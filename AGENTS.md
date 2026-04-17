# Project Guidelines

## Language

- All source code, comments, variable names, function names, test descriptions, and commit messages must be written in **English only**.
- Responses to the user may be in any language.

## Development Process

- All feature work and bug fixes **must** follow TDD (Test-Driven Development).
- Write the failing test first. Watch it fail. Then write the minimal code to make it pass.
- Never write production code without a failing test that demands it.
- If code was written before its test, delete it and start over from the test.
- When generating implementation plans, every task must include explicit RED → GREEN → REFACTOR steps.

## Collector / Rule / Attribute Contract

The engine enforces a strict separation between the context-reading layer and the context-free layer.

- **Collectors** (`AttributeCollector`, `RuleCollector`) are the only layer that reads `CollectorContext`. They transform the raw request into static outputs: attributes or rules.
- **Attributes** are plain values (`Map<string, unknown>`). Once produced by collectors, they carry no reference to the originating request.
- **Rules** are predicates over attributes (`verify(attrs): boolean`). A rule's decision must be derivable from `attrs` alone. Rules must not reference `CollectorContext`, close over request state, or perform side effects.

This contract guarantees that rules are pure functions of attributes: testable in isolation, cacheable, and free from hidden coupling to request shape.

**Violation pattern to avoid:** a rule constructor that captures values from `CollectorContext` (e.g. `context.payload.sub` and `context.requestContext.someField`), then returns the captured comparison from `verify(attrs)` while ignoring `attrs`. This "bakes the decision at collect time" and defeats the contract. The correct shape is: a collector writes both values into attributes under well-known keys, and the rule compares them via `attrs.get(...)`.

## Core Vocabulary Scope

`packages/core` intentionally exports a narrow vocabulary.

- `ATTR_*` constants are restricted to well-known OAuth 2.0 / OIDC and RBAC concepts: scopes, permissions, roles, subject user id (JWT `sub`), client id (JWT `azp`). These are concepts every consumer of the ABAC engine shares, and they originate from transport-neutral standards (not tied to a specific interceptor or wire format).
- Domain-specific attribute keys (business identifiers, tenant flags, protocol-specific fields) **must not** be added to core. They belong to the consuming service, which declares its own constants and reads/writes the same `Attributes` map.
- Core **does not** assume a shape for `CollectorContext.requestContext`. This field is a free-form container whose contents are defined by the interceptor/transport layer of each consuming project. Core provides only the hook — consumers provide the interpretation via their own `AttributeCollector` implementations.

When tempted to add a new `ATTR_*` or a built-in collector that reads a specific `requestContext` key, stop and ask:

- Is this concept universal across every service using the engine (JWT/OIDC/RBAC standards)? If yes, it can live in core.
- Is it a particular consumer's vocabulary, or tied to a specific interceptor's payload shape? If yes, the constant and its collector belong to that consuming service.

### Writing Project-Specific Attribute Collectors

Consuming projects wire their interceptor's `requestContext` into attributes by implementing focused collectors, one per field they care about (or grouped logically). A collector should:

1. Read exactly the fields it intends to promote.
2. Validate the shape of each value (type, non-empty, format) — `requestContext` is unvalidated free-form data.
3. Write into the `Attributes` map under the project's own constant keys.

```typescript
// project-side: collectors/SubscriberDidCollector.mts
import type { AttributeCollector, Attributes, CollectorContext } from "@o3co/auth.policy-verifier.core";

export const ATTR_SUBSCRIBER_DID = "subscriberDid" as const;

export class SubscriberDidCollector implements AttributeCollector {
  async collect(context: CollectorContext): Promise<Attributes> {
    const attrs: Attributes = new Map();
    const v = context.requestContext?.subscriber_did;
    if (typeof v === "string" && v.length > 0) {
      attrs.set(ATTR_SUBSCRIBER_DID, v);
    }
    return attrs;
  }
}
```

The rule then reads `attrs.get(ATTR_SUBSCRIBER_DID)` without ever touching `CollectorContext`.

## Module Resolution

Each package uses Node.js [subpath imports](https://nodejs.org/api/packages.html#subpath-imports) with a conditional `development` / `default` mapping:

```json
"imports": {
  "#/*": {
    "development": "./src/*",
    "default": "./dist/*"
  }
}
```

- **Tests (vitest):** Vite 8+ includes `"development|production"` in its default resolve conditions. During `vitest run`, `isProduction=false` causes it to expand to `"development"`, resolving `#/*` to `./src/*`. This is an implicit dependency on Vite's resolver — Node.js does not enable the `development` condition natively.
- **Published packages:** Consumers resolve `#/*` via the `"default"` condition to `./dist/*`.
- **Local dev server:** The standalone template uses `NODE_OPTIONS='--conditions=development'` to explicitly activate the condition.
- **Cross-package references** (e.g., `builtins` importing from `core`) go through `exports`, which always point to `./dist/`. Run `pnpm -r run build` before running tests in downstream packages.
