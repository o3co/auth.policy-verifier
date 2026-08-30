# @o3co/auth.policy-verifier.cedar

Co-resident [Cedar](https://www.cedarpolicy.com/) policy evaluation for
[auth.policy-verifier](https://github.com/o3co/auth.policy-verifier), as an
optional plugin package.

The whole Cedar policy set is evaluated in-process (official
`@cedar-policy/cedar-wasm`, ~15µs per decision, no network) and enters the
engine's AND-evaluation as **one rule in one group**. TypeScript rule groups
keep working beside it: TS collectors gather the facts, Cedar policies write
judgment over them — **no entity store to build or sync**.

This decouples policy language from PDP topology. Native logic stays
TypeScript — no DSL is ever required — and a deployment that adopts Cedar here
is not binding itself to this verifier: the same `.cedar` files load unchanged
into an embedded evaluator or a Cedar agent later. Design: [#185](https://github.com/o3co/auth.policy-verifier/issues/185).

## Usage

```ts
import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
import { cedarPolicyModule } from "@o3co/auth.policy-verifier.cedar";
import { builtinKeyResolversModule, createApp } from "@o3co/auth.policy-verifier.server";

const app = await createApp({
	pathResolver: import.meta.resolve,
	config,
	modules: [builtinCollectorsModule, builtinKeyResolversModule, cedarPolicyModule],
});
```

```hocon
attribute {
  collectors = [
    { collector = "PayloadSubjectIdCollector" }
    # Promotes action / resourceType / resourceId into attributes — the rule
    # pipeline never sees the request, so the Cedar request is built from these.
    { collector = "RequestFactsCollector" }
  ]
}
rule {
  collectors = [
    { collector = "CedarPolicyRuleCollector"
      # *.cedar files, sorted and concatenated — byte-identical to what a
      # Cedar agent would load. XOR an inline `policies = "..."` string.
      policyDir = "config/policies"

      # "abstain" (default): no determining policy leaves the decision to the
      # other rule groups — the migration posture. Flip to "deny" when the
      # policy set is authoritative.
      onNoDeterminingPolicy = "abstain"

      principal {
        # type = "User"          # default
        # idAttribute = "userId" # default (ATTR_USER_ID)
        attributes { dept = "department" }   # principal.dept == "eng"
        parents { Group = "groups" }         # principal in Group::"admins"
      }
      resource {
        attributes {
          # entity-reference form: resource.owner == principal
          owner = { attribute = "resourceOwner", entityType = "User" }
        }
      }
      context { mfa = "mfaVerified" }        # context.mfa
    }
  ]
}
```

Request-context fields reach Cedar the same way everything else does — as
attributes. Promote them with the builtins' `RequestContextAttributeCollector`
(the declared-allowlist trust boundary, #123) and map them here; nothing
undeclared can reach a policy.

## Semantics

- **Layered PDP.** Cedar's own semantics (forbid overrides permit) hold inside
  the group; the group ANDs with every TypeScript group. During migration both
  are active and compose only toward strictness.
- **Evaluation errors always deny, and log.** Cedar reports a policy that
  reads a missing attribute as `deny` with the cause only in diagnostics — and
  an erroring `forbid` stops forbidding, so the top-level decision can read
  `allow` exactly when it is least trustworthy. The rule checks
  `diagnostics.errors` first: any error is a deny regardless of
  `onNoDeterminingPolicy`, and is logged unless `logEvaluationErrors = false`.
- **Entity synthesis is one hop.** Principal and resource entities are
  synthesized per request from the attribute map — attributes, group
  membership, entity references. Multi-hop dereference and hierarchy walks
  need an entity store; needing them is the signal to move to a full Cedar
  deployment, which the same `.cedar` files already fit.

## Version pinning

`@cedar-policy/cedar-wasm` is pinned exactly: Cedar minor releases can carry
policy-language changes, so upgrades should be deliberate and re-validated,
not fall out of a range resolution.
