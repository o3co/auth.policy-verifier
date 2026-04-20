// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Canonical attribute keys used by built-in collectors and rules. Consumers
// should reference these constants instead of raw strings so that renames stay
// centralized and TypeScript can infer literal types.

export const ATTR_SCOPES = "scopes" as const;
export const ATTR_PERMISSIONS = "permissions" as const;
export const ATTR_ROLES = "roles" as const;
export const ATTR_USER_ID = "userId" as const;
export const ATTR_CLIENT_ID = "clientId" as const;
