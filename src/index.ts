import type { SessionStorage } from "@remix-run/server-runtime";
import { redirect } from "@remix-run/server-runtime";
import { Issuer, errors, generators } from "openid-client";
import type { Client, TokenSet } from "openid-client";
import type { AuthenticateOptions, StrategyVerifyCallback } from "remix-auth";
import { Strategy } from "remix-auth";

/**
 * This interface declares what configuration the strategy needs from the
 * developer to correctly work.
 */
export interface OIDCStrategyOptions {
	issuer: string;
	clientId: string;
	clientSecret: string;
	authorizeEndpoint: string;
	tokenEndpoint: string;
	jwksEndpoint: string;
	redirectURI: string;
	scopes?: string[];
	audiences?: string[];
}

/**
 * This interface declares what the developer will receive from the strategy
 * to verify the user identity in their system.
 */
export interface OIDCStrategyVerifyParams {
	tokens: TokenSet;
	request: Request;
}

export class OIDCStrategy<User> extends Strategy<
	User,
	OIDCStrategyVerifyParams
> {
	name = "remix-auth-openid";
	options: OIDCStrategyOptions;
	private client: Client;

	constructor(
		options: OIDCStrategyOptions,
		verify: StrategyVerifyCallback<User, OIDCStrategyVerifyParams>,
	) {
		super(verify);

		this.options = options;

		// create an openid client
		const issuer = new Issuer({
			issuer: this.options.issuer,
			authorization_endpoint: this.options.authorizeEndpoint,
			token_endpoint: this.options.tokenEndpoint,
			jwks_uri: this.options.jwksEndpoint,
		});

		const client = new issuer.Client({
			client_id: this.options.clientId,
			client_secret: this.options.clientSecret,
			issuer: this.options.issuer,
			redirect_uri: this.options.redirectURI,
		});

		this.client = client;
	}

	async authenticate(
		request: Request,
		sessionStorage: SessionStorage,
		options: AuthenticateOptions,
	): Promise<User> {
		const url = new URL(request.url);

		const session = await sessionStorage.getSession(
			request.headers.get("Cookie"),
		);

		// parse callback parameters from IdP
		const params = this.client.callbackParams(url.toString());

		// if state is not present, we need to start authorization request to the IdP
		if (!params.state) {
			// generate state, nonce, and code_challenge for prevent CSRF
			const state = generators.state();
			const nonce = generators.nonce();
			const codeVerifier = generators.codeVerifier();
			const codeChallenge = generators.codeChallenge(codeVerifier);

			const authzURL = this.client.authorizationUrl({
				code_challenge: codeChallenge,
				code_challenge_method: "S256",
				state: state,
				nonce: nonce,
			});

			// store requested session bind values into the session
			session.set("oidc:state", state);
			session.set("oidc:nonce", nonce);
			session.set("oidc:code_verifier", codeVerifier);

			throw redirect(authzURL, {
				headers: {
					"Set-Cookie": await sessionStorage.commitSession(session),
				},
			});
		}

		// callback from the IdP in the below
		const state = session.get("oidc:state");
		const nonce = session.get("oidc:nonce");
		const verifier = session.get("oidc:code_verifier");

		// exchange code for tokens

		// check if the state is the same as the one we sent
		if (params.state !== state) {
			return await this.failure(
				"Invalid state",
				request,
				sessionStorage,
				options,
				new ReferenceError("Invalid state"),
			);
		}

		// check if code is present
		if (!params.code) {
			return await this.failure(
				"Invalid code",
				request,
				sessionStorage,
				options,
				new ReferenceError("Invalid code"),
			);
		}

		// exchange code for tokens
		try {
			// request to token endpoint with checking state, nonce, response_type and code_verifier
			const tokens = await this.client.callback(this.options.redirectURI, params, {
				state: state,
				nonce: nonce,
				response_type: "code",
				code_verifier: verifier,
			});

			// check caller intended verification
			const user = await this.verify({
				tokens: tokens,
				request: request,
			});

			return this.success(user, request, sessionStorage, options);
		} catch (e) {
			let message: string;

			if (e instanceof errors.OPError) {
				message = e.error_description ?? "Token exchange failed due to IdP";
			} else if (e instanceof errors.RPError) {
				message = e.message ?? "Token exchange failed due to client";
			} else if (e instanceof TypeError) {
				message = e.message ?? "Token exchange failed due to network";
			} else if (e instanceof Error) {
				message = e.message ?? "Token exchange failed due to unknown error";
			} else if (typeof e === "string") {
				message = e;
			} else {
				message = "Token exchange failed due to unknown error";
			}

			return await this.failure(
				message,
				request,
				sessionStorage,
				options,
				e as Error,
			);
		}
	}

	public async refresh(refreshToken: string): Promise<TokenSet> {
		return this.client.refresh(refreshToken);
	}

	public logoutUrl(idToken: string): string {
		return this.client.endSessionUrl({
			id_token_hint: idToken,
		});
	}
}
