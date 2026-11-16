import { authSchemas, createAuthPaths } from '../features/auth/auth.openapi.js';

export function createOpenApiDocument(includeSessionRoutes = true) {
  return {
    openapi: '3.1.0',
    info: {
      title: 'Jobdoor API', version: '1.0.0',
      description: 'Register → verify email → sign in → choose user type → dashboard. All POST requests use application/json. Send cookies with credentials: include. Access JWTs use Authorization: Bearer <token>. Passwords require at least 8 characters and at most 72 UTF-8 bytes; the byte limit is enforced at runtime. Registration returns a generic acceptance response. Provider sign-in is available only when configured. Automated tests use isolated MongoDB and mocked provider responses; live SMTP and provider setup require separate verification.',
    },
    servers: [{ url: '/', description: 'Current API origin' }],
    tags: [
      { name: 'Registration', description: 'Create and verify a normal user account.' },
      { name: 'Sessions', description: 'Sign in, rotate credentials, inspect the current user and sign out.' },
      { name: 'Password recovery', description: 'Recover access with a single-use reset link.' },
      { name: 'Onboarding', description: 'Choose a user type. Job Seeker becomes a candidate.' },
      { name: 'Providers', description: 'Optional Google and GitHub browser-based authentication.' },
    ],
    paths: createAuthPaths(includeSessionRoutes),
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', description: 'Paste the accessToken returned by login or refresh.' },
        refreshCookie: { type: 'apiKey', in: 'cookie', name: 'jobdoor_refresh', description: 'Managed by the browser as an HttpOnly cookie after login. Do not paste a refresh token into the Bearer field.' },
      },
      schemas: authSchemas,
    },
  };
}
