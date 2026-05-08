# sample-go-app

A minimal Go sample app showing **authentication (authn)** and **authorization (authz)** with standards-based SSO.

It uses only the Go standard library and works with any OIDC/OAuth2 identity platform (for example Wardseal, Okta, Auth0) by setting environment variables.

## Features

- OIDC/OAuth2 login using authorization code flow
- Session cookie with HMAC signing
- Protected profile route (`/profile`)
- Role-protected admin route (`/admin`)
- Configurable role claim (default: `roles`)

## Run locally

```bash
export SSO_CLIENT_ID="your-client-id"
export SSO_CLIENT_SECRET="your-client-secret"
export SESSION_SECRET="change-this-to-a-long-random-secret"

# Choose either issuer discovery...
export SSO_ISSUER_URL="https://YOUR_DOMAIN"

# ...or explicit endpoints
# export SSO_AUTH_URL="https://YOUR_DOMAIN/authorize"
# export SSO_TOKEN_URL="https://YOUR_DOMAIN/oauth/token"
# export SSO_USERINFO_URL="https://YOUR_DOMAIN/userinfo"

# Optional overrides
# export SSO_REDIRECT_URL="http://localhost:8080/auth/callback"
# export SSO_SCOPES="openid profile email"
# export SSO_ROLE_CLAIM="roles"
# export SSO_ADMIN_ROLE="admin"

go run .
```

Open <http://localhost:8080> and click **Login with SSO**.

## Provider notes

- **Wardseal/Okta/Auth0**: create a Web app client and set the callback URL to `http://localhost:8080/auth/callback` (or your configured `SSO_REDIRECT_URL`).
- Ensure the provider includes a subject claim (`sub`) and your configured role claim (`roles` by default) if you want `/admin` access checks.

## Tests

```bash
go test ./...
```
