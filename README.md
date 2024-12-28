# OpenID Connect Strategy

This is a strategy for [Remix Auth](https://remix.run/resources/remix-auth) to authenticate users using OpenID Connect(OIDC).
Unlike the existing OIDC strategy for Remix Auth, this strategy faithfully follow the OIDC protocol based on [node-openid-client](https://github.com/panva/node-openid-client). For example, it checks ID token signature, nonce value and other parameters to prevent impersonate attacks.

# Get Started

## Install
```bash
npm i remix-auth-openid
```

## Construct a strategy
To use this strategy, you need to create a strategy object by calling `init` method. The `init` method takes a configuration object and a callback function, which defined by remix auth strategy. The configuration parameters heavily rely on [node-openid-client](https://github.com/panva/node-openid-client).

```typescript
interface User extends OIDCStrategy.BaseUser {
    name?: string;
}

const strategy = await OIDCStrategy.init<User>({
    issuer: "http://localhost:8080/realms/master",
    client_id: "<YOUR CLIENT ID>",
    client_secret: "YOUR CLIENT SECRET",
    redirect_uris: ["http://localhost:3000/callback"],
    scopes: ["openid", "profile"],
}, async ({tokens, request}): Promise<User> => {

    if (!tokens.id_token) {
        throw new Error("No id_token in response");
    }

    if (!tokens.access_token) {
        throw new Error("No access_token in response");
    }

   // You need to return User object
    return {
        ...tokens.claims(),
        accessToken: tokens.access_token,
        idToken: tokens.id_token,
        refreshToken: tokens.refresh_token,
        expiredAt: new Date().getTime() / 1000 + (tokens.expires_in ?? 0),
    }
})

authenticator.use(strategy, "your-oidc-provider-name");
```

## Token refresh
This strategy supports token refresh. You can refresh tokens by calling `refresh` method. If the refresh token is expired, you will be redirected to the `failureRedirect` URL. 

```typescript
const strategy = await OIDCStrategy.init<User>({...})

const user = await authenticator.authenticate(request);
const tokens = await strategy.refresh(user.refreshToken ?? "");
```

## Logout
You can logout via front channel or back channel. 
`

`redirectToLogoutUri` is redirecting to the logout URI of your OIDC provider.
Then, the provider will redirect back to the `post_logout_redirect_uri` which you registered.
```typescript
const user = await authenticator.authenticate(request);
return await authenticator.redirectToLogoutUri(request)
```

back channel logout
```typescript
const user = await authenticator.authenticate(request);
try {
    await strategy.postLogoutUrl(user.idToken ?? "");
    // destroy session with your defined session store
    const header = await sessionStore.destroySession(request);
    throw redirect("/login", { headers: header });
} catch(e) {
    // re-throw when redirect is catched
    if (e instanceof Response) {
        return e;
    }
    throw e;
}
```

## Starter Example
Example code is available in the [Remix Auth OpenID Connect Starter Example](https://github.com/manaty226/remix-auth-openid-example).