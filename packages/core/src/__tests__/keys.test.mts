import { describe, expect, it } from "vitest";
import {
	ATTR_CLIENT_ID,
	ATTR_PERMISSIONS,
	ATTR_ROLES,
	ATTR_SCOPES,
	ATTR_USER_ID,
} from "../keys.mjs";

describe("well-known attribute keys", () => {
	it("exposes the OAuth / OIDC / RBAC attribute key constants", () => {
		expect(ATTR_SCOPES).toBe("scopes");
		expect(ATTR_PERMISSIONS).toBe("permissions");
		expect(ATTR_ROLES).toBe("roles");
		expect(ATTR_USER_ID).toBe("userId");
		expect(ATTR_CLIENT_ID).toBe("clientId");
	});
});
