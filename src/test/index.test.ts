import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	mock,
	test,
} from "bun:test";
import { createCookieSessionStorage } from "@remix-run/node";
import { generators } from "openid-client";
import type { TokenSet } from "openid-client";
import type { AuthenticateOptions } from "remix-auth";
import { AuthorizationError } from "remix-auth";
import { OIDCStrategy } from "..";
import type {
	OIDCStrategyBaseUser,
	OIDCStrategyOptions,
	OIDCStrategyVerifyParams,
} from "..";
import { catchResponse } from "./helper";

import { JsonWebTokenError } from "jsonwebtoken";
import { getMockIdP } from "./mock";

beforeAll(() => {
	getMockIdP().listen();
});

describe("OIDC Strategy", () => {
	const verify = mock();

	const sessionStorage = createCookieSessionStorage({
		cookie: { secrets: ["s3cr3t"] },
	});

	const authOptions: AuthenticateOptions = {
		name: "oidc",
		sessionKey: "auth:session",
		sessionErrorKey: "auth:error",
		sessionStrategyKey: "auth:strategy",
	};

	interface User extends OIDCStrategyBaseUser {}

	const options = Object.freeze({
		issuer: "http://mock.remix-auth-openid",
		client_id: "client-id",
		client_secret: "client-secret",
		authorization_endpoint: "http://mock.remix-auth-openid/authorize",
		token_endpoint: "http://mock.remix-auth-openid/token",
		jwks_uri: "http://mock.remix-auth-openid/.well-known/jwks.json",
		redirect_uris: ["http://mock.example-rp/callback"],
	}) satisfies OIDCStrategyOptions;

	test("should have a name 'remix-auth-oidc'", async () => {
		const strategy = await OIDCStrategy.init<User>(options, verify);
		expect(strategy.name).toBe("remix-auth-openid");
	});

	test("redirects to authorization url if there is no state, nonce, and code_challenge", async () => {
		const strategy = await OIDCStrategy.init<User>(options, verify);
		const request = new Request("https://remix.auth/login", {
			method: "GET",
		});

		const response = await catchResponse(
			strategy.authenticate(request, sessionStorage, authOptions),
		);

		expect(response.status).toBe(302);

		const redirect = new URL(response.headers.get("Location") ?? "");
		const session = await sessionStorage.getSession(
			response.headers.get("set-cookie"),
		);

		expect(redirect.pathname).toBe("/authorize");
		expect(redirect.searchParams.get("response_type")).toBe("code");
		expect(redirect.searchParams.get("client_id")).toBe(options.client_id);
		expect(redirect.searchParams.get("redirect_uri")).toBe(
			options.redirect_uris[0],
		);
		expect(redirect.searchParams.get("state")).toBeDefined();
		expect(redirect.searchParams.get("state")).toBe(session.get("oidc:state"));
		expect(redirect.searchParams.get("nonce")).toBeDefined();
		expect(redirect.searchParams.get("nonce")).toBe(session.get("oidc:nonce"));
		expect(redirect.searchParams.get("code_challenge")).toBeDefined();
		expect(redirect.searchParams.get("code_challenge")).toBe(
			generators.codeChallenge(session.get("oidc:code_verifier")),
		);
		expect(redirect.searchParams.get("code_challenge_method")).toBe("S256");
	});

	test("authorization error if state is mismatch", async () => {
		const strategy = await OIDCStrategy.init<User>(options, verify);
		const request = new Request("https://remix.auth/callback?state=1233456", {
			method: "GET",
		});

		const response = await catchResponse(
			strategy.authenticate(request, sessionStorage, authOptions),
		);

		expect(response.status).toBe(401);
	});

	test("authorization error if code is missing", async () => {
		const strategy = await OIDCStrategy.init<User>(options, verify);

		const stateValue = "123456";

		const session = await sessionStorage.getSession();
		session.set("oidc:state", stateValue);

		const request = new Request(
			`https://remix.auth/callback?state=${stateValue}`,
			{
				method: "GET",
				headers: { cookie: await sessionStorage.commitSession(session) },
			},
		);

		const response = await catchResponse(
			strategy.authenticate(request, sessionStorage, authOptions),
		);

		expect(response.status).toBe(401);

		const message = await response.json();
		expect(message.message).toBe("Invalid code");
	});

	test("authorization success", async () => {
		const verify = async ({ tokens, request }: OIDCStrategyVerifyParams) => {
			if (!tokens.id_token) {
				throw new AuthorizationError("id_token missing");
			}
			if (!tokens.access_token) {
				throw new AuthorizationError("access_token missing");
			}

			return {
				sub: tokens.claims().sub,
				idToken: tokens.id_token,
				accessToken: tokens.access_token,
				refreshToken: tokens.refresh_token,
				expiredAt: new Date().getTime() / 1000 + (tokens.expires_in ?? 0),
			};
		};

		const strategy = await OIDCStrategy.init<User>(options, verify);

		const stateValue = "123456";

		const session = await sessionStorage.getSession();
		session.set("oidc:state", stateValue);

		const request = new Request(
			`https://remix.auth/callback?state=${stateValue}&code=123456`,
			{
				method: "GET",
				headers: { cookie: await sessionStorage.commitSession(session) },
			},
		);

		const user = await strategy.authenticate(
			request,
			sessionStorage,
			authOptions,
		);

		// const user = await strategy.authenticate(
		// 	request,
		// 	sessionStorage,
		// 	authOptions,
		// );

		// expect(user).toEqual({ id: 1 });
	});
});
