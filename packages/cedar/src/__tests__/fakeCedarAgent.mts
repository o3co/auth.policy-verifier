// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * A fake cedar-agent for this package's own tests: a real `node:http` server on
 * an ephemeral loopback port that the HTTP engine reaches through Node's real
 * `fetch`. It evaluates nothing. It records every request it receives — method,
 * path, headers, body — and answers each one with whatever the test programmed,
 * by default the way cedar-agent 0.2.x does: `PUT …/v1/policies` accepted,
 * `POST …/v1/is_authorized` answered with an Allow. Paths are matched on their
 * suffix, so one agent serves several base URLs (`/rule-1`, `/rule-2`), which is
 * how collector tests that share the registered engine stay one agent each.
 */

import { once } from "node:events";
import {
	createServer,
	type IncomingHttpHeaders,
	type IncomingMessage,
	type Server,
	type ServerResponse,
} from "node:http";

/** One request as the agent received it. */
export interface Received {
	method: string;
	/** The request target as sent: path and query. */
	path: string;
	headers: IncomingHttpHeaders;
	body: string;
}

/** How the agent answers one request. `response` is ended, held or destroyed by the handler. */
export type Handler = (request: Received, response: ServerResponse) => void;

/** cedar-agent 0.2.x's answer shape. */
export function decision(
	value: "Allow" | "Deny",
	reason: string[] = [],
	errors: string[] = [],
): Record<string, unknown> {
	return { decision: value, diagnostics: { reason, errors } };
}

/** Ends `response` with `body` as JSON. */
export function sendJson(response: ServerResponse, status: number, body: unknown): void {
	const text = JSON.stringify(body);
	response.writeHead(status, {
		"content-type": "application/json",
		"content-length": Buffer.byteLength(text),
	});
	response.end(text);
}

/** What cedar-agent does with the two calls the engine makes, answering every decision with `answer`. */
export function cedarAgent(answer: Record<string, unknown> = decision("Allow")): Handler {
	return (request, response) => {
		if (request.method === "PUT" && request.path.endsWith("/v1/policies")) {
			sendJson(response, 200, JSON.parse(request.body));
		} else if (request.method === "POST" && request.path.endsWith("/v1/is_authorized")) {
			sendJson(response, 200, answer);
		} else {
			sendJson(response, 404, { reason: "Not Found", description: "no route", code: 404 });
		}
	};
}

/**
 * Accepts the policy set like cedar-agent and hands every authorization call to
 * `authorize` — the shape nearly every failure case takes, since the engine
 * only serves decisions once a load went through.
 */
export function authorizeWith(authorize: Handler): Handler {
	const accept = cedarAgent();
	return (request, response) => {
		if (request.path.endsWith("/v1/is_authorized")) authorize(request, response);
		else accept(request, response);
	};
}

export class FakeCedarAgent {
	/** Every request received since the last `reset`, in arrival order. */
	readonly received: Received[] = [];
	private handler: Handler = cedarAgent();
	/** Responses a handler left unanswered; `reset` and `stop` drop their connections. */
	private readonly held = new Set<ServerResponse>();
	private readonly arrivals: Array<(request: Received) => void> = [];

	private constructor(
		private readonly server: Server,
		/** `http://127.0.0.1:<port>` — no trailing slash. */
		readonly origin: string,
	) {}

	/** Starts an agent on an ephemeral loopback port. */
	static async start(): Promise<FakeCedarAgent> {
		let agent: FakeCedarAgent | undefined;
		const server = createServer((request, response) => {
			void agent?.receive(request, response);
		});
		server.listen(0, "127.0.0.1");
		await once(server, "listening");
		const address = server.address();
		if (address === null || typeof address === "string") throw new Error("expected a TCP address");
		agent = new FakeCedarAgent(server, `http://127.0.0.1:${address.port}`);
		return agent;
	}

	/** Programs how every following request is answered. */
	answer(handler: Handler): void {
		this.handler = handler;
	}

	/** Resolves with the next request that arrives — for a test that acts once the agent has it. */
	nextRequest(): Promise<Received> {
		return new Promise((resolve) => {
			this.arrivals.push(resolve);
		});
	}

	/** Leaves `response` unanswered until `reset` or `stop` drops its connection. */
	hold(response: ServerResponse): void {
		this.held.add(response);
	}

	/**
	 * Back to cedar-agent's defaults, with nothing recorded. Drops only the
	 * connections of responses left unanswered: an idle keep-alive connection
	 * stays open, as it would against a real agent — dropping it under the
	 * client's pool is a failure of its own, not one a test asked for.
	 */
	reset(): void {
		this.received.length = 0;
		this.handler = cedarAgent();
		this.arrivals.length = 0;
		this.dropHeld();
	}

	/** Closes the server and every connection to it. */
	async stop(): Promise<void> {
		this.dropHeld();
		this.server.closeAllConnections();
		this.server.close();
		await once(this.server, "close");
	}

	private dropHeld(): void {
		for (const response of this.held) response.socket?.destroy();
		this.held.clear();
	}

	private async receive(message: IncomingMessage, response: ServerResponse): Promise<void> {
		const chunks: Buffer[] = [];
		for await (const chunk of message) chunks.push(chunk as Buffer);
		const request: Received = {
			method: message.method ?? "",
			path: message.url ?? "",
			headers: message.headers,
			body: Buffer.concat(chunks).toString("utf8"),
		};
		this.received.push(request);
		this.handler(request, response);
		for (const resolve of this.arrivals.splice(0)) resolve(request);
	}
}
