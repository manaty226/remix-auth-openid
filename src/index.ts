import { Cookie, SetCookie } from "@mjackson/headers";
import type {
	Client,
	ClientMetadata,
	IssuerMetadata,
	TokenSet,
} from "openid-client";
import { Issuer, errors, generators } from "openid-client";
import { redirect } from "react-router";
import { Strategy } from "remix-auth/strategy";

export class OIDCStrategy<User extends OIDCStrategy.BaseUser> extends Strategy<
	User,
	OIDCStrategy.VerifyOptions
> {
	name = "remix-auth-openid";
	private options: OIDCStrategy.ClientOptions;
	private client: Client;

	private readonly state_key = "oidc:state";
	private readonly nonce_key = "oidc:nonce";
	private readonly code_verifier_key = "oidc:code_verifier";
	private readonly cookie_key = "oidc:params";

	private constructor(
		client: Client,
		options: OIDCStrategy.ClientOptions,
		verify: Strategy.VerifyFunction<User, OIDCStrategy.VerifyOptions>,
	) {
		super(verify);
		this.client = client;
		this.options = options;
	}

	public static init = async <User extends OIDCStrategy.BaseUser>(
		options: OIDCStrategy.ClientOptions,
		verify: Strategy.VerifyFunction<User, OIDCStrategy.VerifyOptions>,
	) => {
		// create an openid client
		let issuer: Issuer;
		if (!options.authorization_endpoint || !options.token_endpoint) {
			issuer = await Issuer.discover(options.issuer);
		} else {
			issuer = new Issuer({
				...options,
			});
		}
		const client = new issuer.Client({
			...options,
		});
		return new OIDCStrategy(client, options, verify);
	};

	async authenticate(request: Request): Promise<User> {
		const url = new URL(request.url);

		const session = new Cookie(request.headers.get("Cookie") ?? "");

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
				scope: this.options.scopes?.join(" "),
				audience: this.options.audiences?.join(" "),
			});

			// store requested session bind values into the session
			const params = new URLSearchParams();
			params.append(this.state_key, state);
			params.append(this.nonce_key, nonce);
			params.append(this.code_verifier_key, codeVerifier);

			const paramsCookie = new SetCookie({
				name: this.cookie_key,
				value: params.toString(),
				httpOnly: true,
				sameSite: "Lax",
				secure: this.options.https ? true : undefined,
			});

			throw redirect(authzURL, {
				headers: {
					"Set-Cookie": paramsCookie.toString(),
				},
			});
		}

		// callback from the IdP in the below
		const cookie = new URLSearchParams(session.get(this.cookie_key));

		const state = cookie.get(this.state_key) || "";
		const nonce = cookie.get(this.nonce_key) || "";
		const verifier = cookie.get(this.code_verifier_key) || "";

		// exchange code for tokens
		// check if the state is the same as the one we sent
		if (params.state !== state) {
			throw new ReferenceError("Invalid state");
		}

		// check if code is present
		if (!params.code) {
			throw new ReferenceError("Invalid code");
		}

		// exchange code for tokens
		try {
			// request to token endpoint with checking state, nonce, response_type and code_verifier
			const tokens = await this.client.callback(
				this.options.redirect_uris?.[0],
				params,
				{
					state: state,
					nonce: nonce,
					response_type: "code",
					code_verifier: verifier,
					...this.options.idTokenCheckParams,
				},
			);

			// check caller intended verification
			return this.verify({ tokens, request });
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

			throw new Error(message);
		}
	}

	public async refresh(refreshToken: string): Promise<TokenSet> {
		return await this.client.refresh(refreshToken);
	}

	public redirectToLogoutUrl(idToken: string): void {
		throw redirect(this.getLogoutUrl(idToken));
	}

	public async postLogoutUrl(idToken: string): Promise<Response> {
		const url = new URL(this.getLogoutUrl(idToken));

		const body = new URLSearchParams();
		body.append("id_token_hint", idToken);

		const postLogoutRedirectUrl = url.searchParams.get(
			"post_logout_redirect_uri",
		);
		if (postLogoutRedirectUrl) {
			body.append("post_logout_redirect_uri", postLogoutRedirectUrl);
		}

		const clientId = url.searchParams.get("client_id");
		if (clientId) {
			body.append("client_id", clientId);
		}

		const state = url.searchParams.get("state");
		if (state) {
			body.append("state", state);
		}

		const response = await fetch(url.origin + url.pathname, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: body,
		});
		if (!response.ok && response.status >= 400) {
			throw new Error("failed to logout", { cause: response });
		}
		return response;
	}

	private getLogoutUrl(idToken: string): string {
		return this.client.endSessionUrl({
			id_token_hint: idToken,
			state: generators.state(),
		});
	}
}

export namespace OIDCStrategy {
	/**
	 * This interface declares what configuration the strategy needs from the
	 * developer to correctly work.
	 */
	export interface ClientOptions extends ClientMetadata, IssuerMetadata {
		https?: boolean;
		scopes?: string[];
		audiences?: string[];
		idTokenCheckParams?: Record<string, unknown>;
	}

	/**
	 * This interface declares what the developer will receive from the strategy
	 * to verify the user identity in their system.
	 */
	export interface VerifyOptions {
		tokens: TokenSet;
		request: Request;
	}

	export interface BaseUser {
		sub: string;
		accessToken: string;
		idToken?: string;
		refreshToken?: string;
		expiredAt: number;
	}
}
