import type { SessionStorage } from "@remix-run/server-runtime";
import { redirect } from "@remix-run/server-runtime";
import { Issuer, errors, generators } from "openid-client";
import type {
	Client,
	ClientMetadata,
	IssuerMetadata,
	TokenSet,
} from "openid-client";
import type { AuthenticateOptions, StrategyVerifyCallback } from "remix-auth";
import { Strategy } from "remix-auth";

/**
 * This interface declares what configuration the strategy needs from the
 * developer to correctly work.
 */
export interface OIDCStrategyOptions extends ClientMetadata, IssuerMetadata {
	scopes?: string[];
	audiences?: string[];
	idTokenCheckParams?: Record<string, unknown>;
}

/**
 * This interface declares what the developer will receive from the strategy
 * to verify the user identity in their system.
 */
export interface OIDCStrategyVerifyParams {
	tokens: TokenSet;
	request: Request;
}

export interface OIDCStrategyBaseUser {
	sub: string;
	accessToken: string;
	idToken?: string;
	refreshToken?: string;
	expiredAt: number;
}

const STATE_KEY = "oidc:state";
const NONCE_KEY = "oidc:nonce";
const CODE_VERIFIER_KEY = "oidc:code_verifier";

export class OIDCStrategy<User extends OIDCStrategyBaseUser> extends Strategy<
	User,
	OIDCStrategyVerifyParams
> {
	name = "remix-auth-openid";
	options: OIDCStrategyOptions;
	private client: Client;

	private constructor(
		client: Client,
		options: OIDCStrategyOptions,
		verify: StrategyVerifyCallback<User, OIDCStrategyVerifyParams>,
	) {
		super(verify);

		this.options = options;
		this.client = client;
	}

	public static init = async <User extends OIDCStrategyBaseUser>(
		options: OIDCStrategyOptions,
		verify: StrategyVerifyCallback<User, OIDCStrategyVerifyParams>,
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
		return new OIDCStrategy<User>(client, options, verify);
	};

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
				scope: this.options.scopes?.join(" "),
				audience: this.options.audiences?.join(" "),
			});

			// store requested session bind values into the session
			session.set(STATE_KEY, state);
			session.set(NONCE_KEY, nonce);
			session.set(CODE_VERIFIER_KEY, codeVerifier);

			throw redirect(authzURL, {
				headers: {
					"Set-Cookie": await sessionStorage.commitSession(session),
				},
			});
		}

		// callback from the IdP in the below
		const state = session.get(STATE_KEY);
		const nonce = session.get(NONCE_KEY);
		const verifier = session.get(CODE_VERIFIER_KEY);

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

	public async refresh(
		refreshToken: string,
		options: Pick<AuthenticateOptions, "failureRedirect">,
	): Promise<TokenSet | null> {
		try {
			const tokens = await this.client.refresh(refreshToken);
			return tokens;
		} catch (e) {
			if (options.failureRedirect) {
				throw redirect(options.failureRedirect);
			}
		}
		return null;
	}

	public frontChannelLogout(idToken: string) {
		return redirect(this.logoutUrl(idToken));
	}

	public async backChannelLogout(idToken: string) {
		const url = new URL(this.logoutUrl(idToken));

		const body = new URLSearchParams();
		body.append("id_token_hint", idToken);

		const postLogoutRedirectUrl = url.searchParams.get("post_logout_redirect_uri");
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
		
		const response =  await fetch(
			url.origin + url.pathname,
			{
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: body,
			}
		);
	}

	private logoutUrl(idToken: string): string {
		return this.client.endSessionUrl({
			id_token_hint: idToken,
			state: generators.state(),
		});
	}
}
