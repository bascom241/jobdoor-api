# Jobdoor API

Feature-based TypeScript API using Express, MongoDB, Mongoose and JWT authentication.

## API documentation

Start the API, then open [Scalar](http://localhost:3000/api/docs). The OpenAPI 3.1 document is served at `/api/openapi.json`.

The reference includes request and response schemas, examples, status codes, Bearer authentication, refresh-cookie requirements, onboarding types and provider redirects. Input schemas are generated from the same Zod definitions used by the routes. Custom password byte-length validation is explained in the descriptions.

For an authenticated request, sign in using `/api/v1/auth/login`, then paste its `accessToken` into Scalar's Bearer authentication field. Refresh cookies are HttpOnly and managed by the browser. The Scalar page loads its JavaScript from jsDelivr, so viewing the interactive UI requires internet access. The OpenAPI JSON is available locally. Requests go directly to this API; no documentation proxy is configured. Browser rendering has not been manually verified.

## Setup

Requires Node.js 22+, MongoDB and SMTP (a local email catcher can listen on port 1025).

```powershell
npm.cmd install
Copy-Item .env.example .env
```

Fill in MongoDB and SMTP settings. Generate two different secrets with the following command, running it once for each secret, then set `JWT_SECRET` and `VERIFICATION_SECRET` in `.env`:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

```powershell
npm.cmd run dev
```

`WEB_ORIGIN` is the frontend origin, `API_URL` is the public backend base URL, and `RESET_PASSWORD_URL` is the frontend password reset page. These are required alongside the secrets and email settings. Do not commit `.env`.

## Authentication flow

1. `POST /api/v1/auth/register` with `name`, `email`, and `password` creates an unverified normal user. Passwords require 8 characters and at most 72 UTF-8 bytes. Extra fields are rejected.
2. `POST /api/v1/auth/verify-email` with `email` and a six-digit `code` verifies the account. Codes expire in 10 minutes and allow five incorrect attempts.
3. `POST /api/v1/auth/resend-verification` with `email` requests a new code after a 30-second cooldown.
4. `POST /api/v1/auth/login` with `identifier`, `password`, and optional `keepMeSignedIn` returns a 15-minute access JWT and sets an HttpOnly refresh cookie. Identifier accepts an email or a username chosen during onboarding.
5. `GET /api/v1/auth/me` with a Bearer token returns safe user fields and `nextStep`.
6. `POST /api/v1/auth/onboarding` with a Bearer token and `userType` completes user-type selection once. Optional `username` must be unique and contain 3–30 lowercase letters, digits or underscores.
7. `POST /api/v1/auth/refresh` rotates the refresh cookie and returns another access JWT. `POST /api/v1/auth/logout` revokes that session and clears its cookie. Both require `Content-Type: application/json`; send `{}`.

The Job Seeker type (`job_seeker`) becomes a candidate. Employer, Recruiter, Freelancer, Employee and Manager/HR Admin record intended use while retaining the normal user role. Organisation permissions require a separate authorized workflow.

Use `credentials: 'include'` for browser requests that receive or send cookies. Keep the access token in memory and serialize refresh calls. A reused refresh token revokes the session. Session lifetimes are absolute: 24 hours by default, or 30 days when Keep me signed in is selected. The default cookie is a browser-session cookie; the persistent option adds an expiry. Cookies are Secure in production and SameSite=Lax; frontend and API should share a site. Browser cross-site POSTs are rejected.

Password recovery uses `POST /forgot-password` with `email`, then `POST /reset-password` with the emailed `token` and new `password`, under the same `/api/v1/auth` prefix. Reset links expire in 30 minutes and are single-use. Resetting a password revokes all existing sessions. A six-digit password-reset flow is not implemented; email verification uses six-digit codes.

## Google and GitHub

Provider buttons should be displayed only for entries returned by `GET /api/v1/auth/providers`. Set the matching client ID and secret in `.env` to enable a provider, and register these callback URLs in its developer console:

```text
http://localhost:3000/api/v1/auth/google/callback
http://localhost:3000/api/v1/auth/github/callback
```

Use the deployed `API_URL` in production. Start sign-in with a top-level browser navigation to `/api/v1/auth/google` or `/api/v1/auth/github`. After the provider callback, the browser is redirected to `WEB_ORIGIN/auth/callback`; that frontend page must call `/refresh` with `{}` and cookies, then `/me`. Provider authentication uses state checks, PKCE and a verified provider email. Existing accounts are not linked automatically based on email. Live provider sign-in requires configured credentials and separate verification.

Implementation references: [Google authorization flow](https://developers.google.com/identity/protocols/oauth2/web-server), [GitHub authorization flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps), [Scalar Express integration](https://scalar.com/products/api-references/integrations/express).

## Structure

- `src/features/auth/`: schemas, routes, registration, sessions, email recovery, provider authentication, audit events and feature OpenAPI definitions.
- `src/features/users/`: user persistence and role/status/user-type enums.
- `src/docs/`: OpenAPI composition and Scalar routes.
- `src/shared/`: HTTP errors and safe error logging.
- `src/app.ts`: middleware and route composition.
- `src/config.ts`: environment validation.
- `src/server.ts`: database startup and server lifecycle.

## Checks

```powershell
npm.cmd run typecheck
npm.cmd run build
npm.cmd test
```

Typechecking includes source and tests; the production build emits source only. Documentation and registration tests do not need MongoDB. Integration tests start a separate temporary MongoDB instance using `mongodb-memory-server`; they never use `MONGODB_URI`. The first run can download a large test binary. To use your installed MongoDB executable instead:

```powershell
$env:MONGOMS_SYSTEM_BINARY = 'C:/Program Files/MongoDB/Server/9.0/bin/mongod.exe'
npm.cmd test
```

Run only the database-independent checks with:

```powershell
node --import tsx --test tests/docs.test.ts tests/registration.test.ts
```

## Operational limitations

Email and audit writes are separate from account writes. SMTP failures retain pending accounts; users can resend after cooldown. Durable email retries and transactional audit delivery remain production follow-up work. Rate limits use process-local storage; multiple instances need shared storage. Trusted proxies must be configured explicitly for the deployment. No frontend screens are included. Protect candidate resources with account/session checks and explicit authorization as those features are added.
