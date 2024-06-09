import { createPublicKey, generateKeyPairSync } from "node:crypto";
import type { Jwt, JwtHeader, JwtPayload } from "jsonwebtoken";
import { sign } from "jsonwebtoken";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";

export interface TokenResponseBody {
	id_token: string;
	access_token: string;
	token_type: string;
	expires_in?: number;
	refresh_token?: string;
	scope?: string;
}

export function getMockIdP() {

	const { publicKey, privateKey } = generateKeyPairSync("rsa", {
		modulusLength: 4096,
		publicKeyEncoding: {
			type: "spki",
			format: "pem",
		},
		privateKeyEncoding: {
			type: "pkcs8",
			format: "pem",
		},
	});

	const pubKey = createPublicKey(publicKey);

	let jwk = pubKey.export({ format: "jwk" });
	jwk = {
		...jwk,
		alg: "RS256",
		use: "sig",
		kid: "some-kid",
	};


	return setupServer(
		http.post("http://mock.remix-auth-openid/token", async () => {
			const payload = {
				iss: "http://mock.remix-auth-openid",
				sub: "some-subject",
				aud: "client-id",
				nonce: "dummy-nonce",
				auth_time: Math.floor(Date.now() / 1000),
				iat: Math.floor(Date.now() / 1000),
				exp: Math.floor(Date.now() / 1000) + 60 * 60,
			} satisfies JwtPayload;

			const token = sign(payload, privateKey, {
				algorithm: "RS256",
				keyid: "some-kid",
			});
		
			return HttpResponse.json({
				id_token: token,
				access_token: token,
				expires_in: 3600,
				refresh_token: "mocked-refresh-token",
				scope: ["openid"].join(" "),
				token_type: "Bearer",
			} satisfies TokenResponseBody);
		}),
		http.get("http://mock.remix-auth-openid/.well-known/jwks.json", async () => {
			return HttpResponse.json({
				keys: [jwk],
			});
		}),
	);
}
