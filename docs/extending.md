# Extending auth.policy-verifier

This guide documents how to write custom `Rule` and `AttributeCollector` implementations. It complements the built-in implementations shipped in [`@o3co/auth.policy-verifier.builtins`](../packages/builtins/README.md).

## Positioning: builtins is a basic set, not an exhaustive catalog

`@o3co/auth.policy-verifier.builtins` ships a deliberately small set of rules and collectors that cover common cases: permission / scope checks, attribute equality / membership / comparison, subject-ID extraction, static permissions and roles.

This package is **not** intended to be an exhaustive operator catalog comparable to [OPA](https://www.openpolicyagent.org/) or [Cedar](https://www.cedarpolicy.com/). Those systems require a broad built-in operator surface because policy authors work inside a DSL — they cannot reach outside the operators the engine provides.

auth.policy-verifier takes a different stance. Policies are TypeScript code, and `Rule` / `AttributeCollector` are small, stable interfaces. Writing a custom `Rule` for project-specific logic is a first-class operation, not a workaround. If your requirement is not expressible with a builtin, write your own — do not wait for the builtin to grow.

**When to write a custom Rule instead of using a builtin:**

- You need regex matching, CIDR matching, time windows, set algebra, or nested-attribute paths.
- Your policy depends on state that a generic rule cannot access (e.g. a database lookup).
- You want a domain-specific denial code or message that does not map cleanly onto a builtin.

**When to use a builtin:**

- Your logic is expressible as equal / not-equal / in / not-in / numeric compare over one or two attributes.
- You are prototyping and have not yet defined domain-specific vocabulary.

If multiple projects in your organization end up writing the same custom rule, extract it into a shared package (e.g. `@yourorg/authz.rules.ipcidr`). Do not pressure `builtins` to grow — it is intentionally a basic set.

## Writing a custom Rule

`Rule` is defined in `@o3co/auth.policy-verifier.core`:

```ts
interface Rule {
  ruleType: string;
  code: string;
  message: string;
  verify(attrs: Attributes): boolean;
}
```

- `verify(attrs)` is the predicate. Return `true` to pass, `false` to fail. **Safe-deny convention:** missing, wrong-type, or malformed attributes must return `false`, not throw. Throwing turns a policy failure into an error response and leaks evaluation state.
- `ruleType` is used by the evaluator to group rules. Rules sharing a `ruleType` are OR-combined (any one passing satisfies the group). Rules with different `ruleType`s are AND-combined across groups (all groups must be satisfied). **Default `ruleType`s must encode enough of the rule's configuration to avoid silent collisions.** For example, `AttrLiteralEqual` uses `attr_literal_equal:${a}:${typeof v}:${String(v)}` — the `typeof v` segment prevents `v=true` and `v="true"` from collapsing into the same `ruleType` and being OR-combined against intent.
- `code` is a short, stable identifier (e.g. `"no_permission"`, `"attr_not_equal"`) suitable for downstream programmatic handling.
- `message` is a human-readable denial message. Keep it informative but do not leak sensitive attribute values.

### Worked example: `UserLevelAtLeast`

A rule that passes when `userLevel` is a number greater than or equal to a configured threshold:

```ts
import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";

export interface UserLevelAtLeastConfig {
  threshold: number;
  group?: string;
}

export class UserLevelAtLeast implements Rule {
  readonly ruleType: string;
  readonly code = "user_level_too_low";
  readonly message: string;

  constructor(private readonly config: UserLevelAtLeastConfig) {
    if (typeof config.threshold !== "number" || Number.isNaN(config.threshold)) {
      throw new Error("UserLevelAtLeast: 'threshold' must be a number and not NaN");
    }
    // Encode threshold into ruleType so two UserLevelAtLeast instances with
    // different thresholds are AND-combined (both must pass), not OR-combined.
    this.ruleType = config.group ?? `user_level_at_least:${String(config.threshold)}`;
    this.message = `User level must be at least ${String(config.threshold)}.`;
  }

  verify(attrs: Attributes): boolean {
    const level = attrs.get("userLevel");
    if (typeof level !== "number") return false;
    return level >= this.config.threshold;
  }
}
```

Notes:

- Config is validated at construction time (fail fast). `verify()` is hot-path — it should not re-validate config.
- `verify()` returns `false` for missing or non-number attributes (safe-deny). It does not throw.
- The default `ruleType` includes the threshold so `new UserLevelAtLeast({ threshold: 3 })` and `new UserLevelAtLeast({ threshold: 5 })` produce distinct groups and are AND-combined. If you want them OR-combined (e.g. "level ≥ 3 OR some other ladder rung"), pass a shared `group` string to both.

## Writing a custom AttributeCollector

`AttributeCollector` is defined in `@o3co/auth.policy-verifier.core`:

```ts
interface AttributeCollector {
  collect(context: CollectorContext): Promise<Attributes>;
}
```

- One collector should produce a **focused set of attribute keys**. Do not bundle unrelated extractions. If you are extracting IP address and user agent, write two collectors.
- Prefer string constants for attribute keys. See `ATTR_SCOPES`, `ATTR_PERMISSIONS`, `ATTR_ROLES`, `ATTR_USER_ID`, `ATTR_CLIENT_ID` in `@o3co/auth.policy-verifier.core`. For project-specific keys, define your own constants and **do not reuse core keys with different semantics**.
- The `AttributePipeline` runs all collectors in parallel and merges their results: array values are concatenated, scalar/object values follow last-writer-wins. Design accordingly — do not rely on collector ordering.
- `CollectorContext.requestContext` is intentionally unshaped. The engine does not ship a generic `requestContext` collector because its shape is defined by each consuming project's transport or interceptor. Write a focused collector per field you need to promote; validate shapes inside that collector.

### Worked example: `ClientIpCollector`

A collector that extracts the client IP from `requestContext` into an attribute:

```ts
import type {
  AttributeCollector,
  Attributes,
  CollectorContext,
} from "@o3co/auth.policy-verifier.core";

// Project-specific attribute key constant — keep it local to your project.
export const ATTR_CLIENT_IP = "clientIp" as const;

export class ClientIpCollector implements AttributeCollector {
  async collect(context: CollectorContext): Promise<Attributes> {
    const ip = context.requestContext?.clientIp;
    if (typeof ip !== "string" || ip.length === 0) {
      return new Map(); // emit nothing — downstream rules see missing attribute and safe-deny
    }
    return new Map([[ATTR_CLIENT_IP, ip]]);
  }
}
```

Notes:

- When the shape is wrong or the value is missing, emit an empty `Map`. Do not set the key to `null` or `undefined` — downstream rules distinguishing "missing" vs "present-and-falsy" would be brittle.
- Validate the shape inside the collector. The type of `requestContext` is `Record<string, unknown>`; a collector that consumes it is the right place to narrow.

## RuleCollector: when to write one

`RuleCollector` is the factory that turns a `CollectorContext` into a `Rule[]`. Built-in examples are `ResourceActionPermissionRuleCollector` and `ResourceActionScopeRuleCollector` under [`packages/builtins/src/rules/collectors/`](../packages/builtins/src/rules/collectors/). They construct a `HasPermission` / `HasScope` rule from the request's resource and action.

Write a custom `RuleCollector` when your rule construction depends on request-time context (resource, action, headers). If your rule is constant across all requests, instantiate the `Rule` directly at composition time instead — no collector needed.

## Further reading

- [`@o3co/auth.policy-verifier.core` README](../packages/core/README.md) — interfaces, evaluator, pipelines.
- [`@o3co/auth.policy-verifier.builtins` README](../packages/builtins/README.md) — reference for built-in rules and collectors.
- [AGENTS.md — Core Vocabulary Scope](../AGENTS.md#core-vocabulary-scope) — rationale for why `builtins` does not ship a generic `requestContext` collector.
