export interface Resource {
	raw: string;
	resourceType: string;
	resourceId?: string;
}

export interface ResourceParser {
	parse(raw: string): Resource;
}

export interface CollectorContext {
	payload: VerifierPayload;
	resource: Resource;
	action: string;
	headers?: Record<string, string>;
	requestContext?: Record<string, unknown>;
}

export type Attributes = Map<string, unknown>;

export interface AttributeCollector {
	collect(context: CollectorContext): Promise<Attributes>;
}

export interface Rule {
	ruleType: string;
	code: string;
	message: string;
	verify(attrs: Attributes): boolean;
}

export interface RuleCollector {
	collect(context: CollectorContext): Promise<Rule[]>;
}

export type Decision = { decision: "allow" } | { decision: "deny"; code: string; message: string };

export interface Role {
	name: string;
	permissions: string[];
}

export interface VerifierPayload {
	sub?: string;
	azp?: string;
	scope?: string;
	iss?: string;
	aud?: string | string[];
	exp?: number;
	iat?: number;
	token?: string;
	tokenType?: string;
	[key: string]: unknown;
}
