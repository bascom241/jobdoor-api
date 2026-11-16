# Jobdoor API

TypeScript, Express, MongoDB and Mongoose backend. First implemented endpoint: password registration. JWT dependencies are installed for the upcoming login/refresh implementation; registration does not issue credentials before verification.

## Feature structure

```text
src/
  features/
    auth/
      auth.enums.ts
      auth-event.model.ts
      auth.routes.ts
      registration.dependencies.ts
      registration.schema.ts
      registration.service.ts
    users/
      user.enums.ts
      user.model.ts
  shared/
    logger.ts
  app.ts
  config.ts
  server.ts
tests/
  registration.test.ts
```

Each feature owns its routes, business logic, models and enums. Add future candidate onboarding under `features/candidates`.

## Run

Requires Node.js 22+, MongoDB, and an SMTP server (for example a local email catcher on port 1025).

```powershell
npm.cmd install
Copy-Item .env.example .env
# Configure MongoDB, SMTP and frontend URLs in .env.
npm.cmd run dev
```

```text
POST /api/v1/auth/register
Content-Type: application/json

{"name":"Jane Doe","email":"jane@example.com","password":"a secure passphrase"}
```

Valid new and existing emails receive HTTP 202 with the same generic response to reduce account enumeration. Invalid input receives 400; request throttling returns 429. Passwords require at least 12 characters and at most 72 UTF-8 bytes. Extra fields are rejected.

Accounts start with `UserRole.User` and `AccountStatus.PendingVerification`. Clients cannot choose permissions. Candidate promotion belongs to subsequent onboarding. Passwords use bcrypt with cost 12. Verification emails carry a random 32-byte token; only its SHA-256 hash and 24-hour expiry are stored. The unique MongoDB email index prevents concurrent duplicate registrations. Successful registrations are recorded in `authevents`.

Configure the frontend verification URL in `.env`. Verification token consumption, login, JWT access/refresh token management, logout, password reset, provider authentication and candidate onboarding are subsequent endpoints and are not implemented yet.

SMTP delivery failures are logged with a generic event name; the pending account is retained and `verificationEmailSentAt` stays null. A resend/retry mechanism is required before production use. Audit storage and account creation are separate writes; a durable transactional outbox should be added for production delivery and audit guarantees. Use HTTPS, shared rate-limit storage for multiple instances, and configure trusted proxies explicitly if deploying behind a proxy.

## Checks

```powershell
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
```

Tests exercise the HTTP registration flow with injected persistence/email adapters. They do not require MongoDB or SMTP and do not replace integration testing with those services.
