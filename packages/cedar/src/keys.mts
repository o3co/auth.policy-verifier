// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Attribute keys written by `RequestFactsCollector` and read (by default) by
// `CedarPolicyRuleCollector`. They exist because the rule pipeline never sees
// `CollectorContext`: a rule is a function of the merged attributes alone, so
// the request facts a Cedar policy set decides over — action, resource type,
// resource id — must be promoted into attributes by a collector first. These
// are this package's vocabulary, not core's: core's `ATTR_*` constants are
// reserved for OAuth/OIDC/RBAC concepts (AGENTS.md "Core Vocabulary Scope"),
// and "the parsed request" is not one.

export const ATTR_REQUEST_ACTION = "requestAction" as const;
export const ATTR_REQUEST_RESOURCE_TYPE = "requestResourceType" as const;
export const ATTR_REQUEST_RESOURCE_ID = "requestResourceId" as const;
export const ATTR_REQUEST_RESOURCE_RAW = "requestResourceRaw" as const;
