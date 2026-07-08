import { Cookie, SetCookie } from "@mjackson/headers";
import * as client from "openid-client";
import { redirect } from "react-router";
import { Strategy } from "remix-auth/strategy";

export class OIDCStrategy<User extends OIDCStrategy.BaseUser> extends Strategy<
	User,
	OIDCStrategy.VerifyOptions
> {
	name = "remix-auth-openid";
	private options: OIDCStrategy.ClientOptions;
	private config: client.Configuration;

	private readonly state_key = "oidc:state";
	private readonly nonce_key = "oidc:nonce";
	private readonly code_verifier_key = "oidc:code_verifier";
	private readonly cookie_key = "oidc:params";

	private constructor(
		config: client.Configuration,
		options: OIDCStrategy.ClientOptions,
		verify: Strategy.VerifyFunction<User, OIDCStrategy.VerifyOptions>,
	) {
		super(verify);
		this.config = config;
		this.options = options;
	}

	public static init = async <User extends OIDCStrategy.BaseUser>(
		options: OIDCStrategy.ClientOptions,
		verify: Strategy.VerifyFunction<User, OIDCStrategy.VerifyOptions>,
	) => {
		const issuerUrl = new URL(options.issuer);

		// Strategy-specific options are extracted; the rest is OIDC metadata
		const {
			https: _https,
			scopes: _scopes,
			audiences: _audiences,
			idTokenCheckParams: _idTokenCheckParams,
			allowInsecureRequests,
			...oidcMetadata
		} = options;

		let config: client.Configuration;
		if (!options.authorization_endpoint || !options.token_endpoint) {
			config = await client.discovery(
				issuerUrl,
				options.client_id,
				oidcMetadata as Partial<client.ClientMetadata>,
				undefined,
				allowInsecureRequests
					? { execute: [client.allowInsecureRequests] }
					: undefined,
			);
		} else {
			config = new client.Configuration(
				oidcMetadata as client.ServerMetadata,
				options.client_id,
				oidcMetadata as Partial<client.ClientMetadata>,
			);
			if (allowInsecureRequests) {
				client.allowInsecureRequests(config);
			}
		}
		return new OIDCStrategy(config, options, verify);
	};

	async authenticate(request: Request): Promise<User> {
		const url = new URL(request.url);

		const session = new Cookie(request.headers.get("Cookie") ?? "");

		// if state is not present, we need to start authorization request to the IdP
		if (!url.searchParams.has("state")) {
			const state = client.randomState();
			const nonce = client.randomNonce();
			const codeVerifier = client.randomPKCECodeVerifier();
			const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);

			const authzParams: Record<string, string> = {
				code_challenge: codeChallenge,
				code_challenge_method: "S256",
				state: state,
				nonce: nonce,
			};

			if (this.options.scopes) {
				authzParams.scope = this.options.scopes.join(" ");
			}
			if (this.options.audiences) {
				authzParams.audience = this.options.audiences.join(" ");
			}
			if (this.options.redirect_uris?.[0]) {
				authzParams.redirect_uri = this.options.redirect_uris[0];
			}

			const authzURL = client.buildAuthorizationUrl(this.config, authzParams);

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

			throw redirect(authzURL.toString(), {
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

		// check if the state from cookie matches the one in the URL
		if (url.searchParams.get("state") !== state) {
			throw new ReferenceError("Invalid state");
		}
		// check if code is present
		if (!url.searchParams.has("code")) {
			throw new ReferenceError("Invalid code");
		}

		// exchange code for tokens
		try {
			const tokens = await client.authorizationCodeGrant(this.config, request, {
				expectedState: state,
				expectedNonce: nonce,
				pkceCodeVerifier: verifier,
				...this.options.idTokenCheckParams,
			});

			// check caller intended verification
			return this.verify({ tokens, request });
		} catch (e) {
			let message: string;

			if (e instanceof client.ResponseBodyError) {
				message = e.error_description ?? "Token exchange failed due to IdP";
			} else if (e instanceof client.AuthorizationResponseError) {
				message =
					e.error_description ?? "Token exchange failed due to invalid response";
			} else if (e instanceof client.ClientError) {
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

	public async refresh(
		refreshToken: string,
	): Promise<
		client.TokenEndpointResponse & client.TokenEndpointResponseHelpers
	> {
		return await client.refreshTokenGrant(this.config, refreshToken);
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
			signal: AbortSignal.timeout(10000),
		});
		if (!response.ok && response.status >= 400) {
			throw new Error("failed to logout", { cause: response });
		}
		return response;
	}

	private getLogoutUrl(idToken: string): string {
		return client
			.buildEndSessionUrl(this.config, {
				id_token_hint: idToken,
				state: client.randomState(),
			})
			.toString();
	}
}

export namespace OIDCStrategy {
	/**
	 * This interface declares what configuration the strategy needs from the
	 * developer to correctly work.
	 */
	export interface ClientOptions {
		issuer: string;
		client_id: string;
		client_secret?: string;
		redirect_uris?: string[];
		authorization_endpoint?: string;
		token_endpoint?: string;
		jwks_uri?: string;
		end_session_endpoint?: string;
		https?: boolean;
		scopes?: string[];
		audiences?: string[];
		/** When set to true, allows HTTP (non-TLS) requests. Use only for local development and testing. */
		allowInsecureRequests?: boolean;
		/** Additional ID Token checks. Only `maxAge` and `idTokenExpected` are allowed; security-critical checks are handled internally. */
		idTokenCheckParams?: Pick<
			client.AuthorizationCodeGrantChecks,
			"maxAge" | "idTokenExpected"
		>;
		[key: string]: unknown;
	}

	/**
	 * This interface declares what the developer will receive from the strategy
	 * to verify the user identity in their system.
	 */
	export interface VerifyOptions {
		tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers;
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
