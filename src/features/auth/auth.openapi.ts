import { z } from 'zod';
import { AccountStatus, UserRole, UserType } from '../users/user.enums.js';
import { registrationSchema } from './registration.schema.js';
import { emailSchema, loginSchema, onboardingSchema, resetPasswordSchema, verifyEmailSchema } from './auth.schemas.js';

const schemaRef = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const response = (description: string, schema: object) => ({
  description, content: { 'application/json': { schema } },
});
const message = (text: string) => ({
  type: 'object', required: ['message'], properties: { message: { type: 'string', example: text } },
});
const error = (description: string) => response(description, schemaRef('Error'));
const body = (name: string, example: object) => ({
  required: true, content: { 'application/json': { schema: schemaRef(name), example } },
});
const operationErrors = {
  '400': error('Invalid input or expired code/token'),
  '413': error('Request body exceeds 16 KB'),
  '429': { description: 'Too many requests. Retry after the time indicated by the Retry-After header.' },
  '500': error('Unexpected server error'),
};
const jsonErrors = {
  ...operationErrors,
  '403': error('Origin is not allowed'),
  '415': error('Content-Type must be application/json'),
};
const sessionResponse = response('Access JWT returned; refresh token stored in an HttpOnly cookie.', schemaRef('Credentials'));
const userResponse = response('Current user and frontend navigation state', {
  type: 'object', required: ['user'], properties: { user: schemaRef('User') },
});

export function createAuthPaths(includeSessionRoutes: boolean) {
  const register = {
    '/api/v1/auth/register': { post: {
      tags: ['Registration'], operationId: 'register', summary: 'Create a normal user account',
      description: 'Creates an unverified user, hashes the password, and emails a six-digit verification code valid for 10 minutes. New and existing emails receive the same response. No credentials are issued. Passwords require 8 characters and at most 72 UTF-8 bytes. Clients cannot select a role.',
      security: [], requestBody: body('RegisterInput', { name: 'Jane Doe', email: 'jane@example.com', password: 'Password123!' }),
      responses: {
        '202': response('Registration accepted; does not disclose whether the email exists or guarantee email delivery.',
          message('If registration is available for this email, verification instructions will be sent.')),
        ...operationErrors,
      },
    } },
  };
  if (!includeSessionRoutes) return register;
  return { ...register,
    '/api/v1/auth/verify-email': { post: {
      tags: ['Registration'], operationId: 'verifyEmail', summary: 'Verify a six-digit email code',
      description: 'Codes expire after 10 minutes, can be consumed once, and allow at most five incorrect attempts. A verified user must then sign in.',
      security: [], requestBody: body('VerifyEmailInput', { email: 'jane@example.com', code: '012345' }),
      responses: { '200': response('Email verified', message('Email verified. You can now sign in.')), ...jsonErrors },
    } },
    '/api/v1/auth/resend-verification': { post: {
      tags: ['Registration'], operationId: 'resendVerification', summary: 'Request another email code',
      description: 'Minimum 30-second cooldown. Replaces the previous code and resets its attempts. Unknown or already verified emails receive the same generic response. The cooldown value is not a delivery confirmation.',
      security: [], requestBody: body('EmailInput', { email: 'jane@example.com' }),
      responses: { '202': response('Request accepted', {
        type: 'object', properties: {
          message: { type: 'string', example: 'If eligible, a verification code will be sent.' },
          resendAfterSeconds: { type: 'integer', example: 30 },
        }, required: ['message', 'resendAfterSeconds'],
      }), ...jsonErrors },
    } },
    '/api/v1/auth/login': { post: {
      tags: ['Sessions'], operationId: 'login', summary: 'Sign in with email or username',
      description: 'Requires a verified account. identifier accepts email or an optional username chosen during onboarding. Access JWTs last 15 minutes. keepMeSignedIn=false uses a browser-session cookie and a 24-hour server session; true sets a persistent cookie and a 30-day server session. Session expiry is absolute, not extended on refresh.',
      security: [], requestBody: body('LoginInput', { identifier: 'jane@example.com', password: 'Password123!', keepMeSignedIn: false }),
      responses: { '200': sessionResponse, ...jsonErrors, '401': error('Invalid credentials'), '403': error('Email is not verified or Origin is not allowed') },
    } },
    '/api/v1/auth/refresh': { post: {
      tags: ['Sessions'], operationId: 'refreshSession', summary: 'Rotate the refresh token and renew access',
      description: 'Send the jobdoor_refresh browser cookie. Rotation replaces it on every call. Reuse of an old refresh token revokes the session. Serialize refresh calls; do not automatically retry a request with an old token. Send an empty JSON object. Scalar can use cookies already set for this origin; JavaScript cannot read or manually populate HttpOnly cookies.',
      security: [{ refreshCookie: [] }], requestBody: { required: true, content: { 'application/json': { schema: { type: 'object' }, example: {} } } },
      responses: { '200': sessionResponse, ...jsonErrors, '401': error('Refresh credentials are invalid, expired, revoked, or reused') },
    } },
    '/api/v1/auth/logout': { post: {
      tags: ['Sessions'], operationId: 'logout', summary: 'End the current session',
      description: 'Revokes the session identified by the refresh cookie, invalidating its access JWTs, and clears the cookie. Idempotent if no session is present. Send an empty JSON object.',
      security: [{ refreshCookie: [] }], requestBody: { required: true, content: { 'application/json': { schema: { type: 'object' }, example: {} } } },
      responses: { '204': { description: 'Logged out; no response body' }, ...jsonErrors },
    } },
    '/api/v1/auth/forgot-password': { post: {
      tags: ['Password recovery'], operationId: 'forgotPassword', summary: 'Request a password reset email',
      description: 'For verified password accounts, sends a link containing a single-use token valid for 30 minutes. Cooldown is 30 seconds. Unknown accounts and provider-only accounts receive the same response. This is a reset-link flow; six-digit password-reset verification is not implemented.',
      security: [], requestBody: body('EmailInput', { email: 'jane@example.com' }),
      responses: { '202': response('Request accepted', message('If eligible, password reset instructions will be sent.')), ...jsonErrors },
    } },
    '/api/v1/auth/reset-password': { post: {
      tags: ['Password recovery'], operationId: 'resetPassword', summary: 'Set a new password using the emailed token',
      description: 'Consumes a valid reset token, hashes the new password and revokes all existing sessions. The user must sign in again. The token is read from the frontend reset-link query string.',
      security: [], requestBody: body('ResetPasswordInput', { token: 'a'.repeat(64), password: 'NewPassword123!' }),
      responses: { '200': response('Password updated', message('Password reset. Sign in with your new password.')), ...jsonErrors },
    } },
    '/api/v1/auth/me': { get: {
      tags: ['Sessions'], operationId: 'getCurrentUser', summary: 'Get the current verified user',
      description: 'Checks JWT signature, expiry, live session and current account state. nextStep tells the frontend whether to show user-type selection or the dashboard. It is not an HTTP redirect.',
      security: [{ bearerAuth: [] }], responses: { '200': userResponse, '401': error('Missing, invalid, expired, or revoked credentials'), '500': error('Unexpected server error') },
    } },
    '/api/v1/auth/onboarding': { post: {
      tags: ['Onboarding'], operationId: 'completeOnboarding', summary: 'Select how the user will use the app',
      description: 'Allowed once per verified user. job_seeker becomes candidate. Other types retain the user role and record intent only; selecting Manager/HR Admin does not grant administrative permissions. Optional username is unique and accepts 3–30 lowercase letters, digits and underscores.',
      security: [{ bearerAuth: [] }], requestBody: body('OnboardingInput', { userType: UserType.JobSeeker, username: 'jane_doe' }),
      responses: { '200': userResponse, ...jsonErrors, '401': error('Authentication is required'), '409': error('Username unavailable or onboarding already completed') },
    } },
    '/api/v1/auth/providers': { get: {
      tags: ['Providers'], operationId: 'listProviders', summary: 'List enabled sign-in providers', security: [],
      responses: { '200': response('Only providers with configured credentials are listed.', {
        type: 'object', required: ['providers'], properties: { providers: { type: 'array', items: { type: 'string', enum: ['google', 'github'] }, example: ['google', 'github'] } },
      }) },
    } },
    '/api/v1/auth/{provider}': { get: {
      tags: ['Providers'], operationId: 'startProviderLogin', summary: 'Start Google or GitHub sign-in',
      description: 'Open as a top-level browser navigation, not an AJAX request. Sets a short-lived HttpOnly state cookie and redirects to the provider with PKCE. Disabled providers return 503.',
      security: [], parameters: [{ name: 'provider', in: 'path', required: true, schema: { type: 'string', enum: ['google', 'github'] } }],
      responses: { '302': { description: 'Redirect to the provider authorization screen', headers: { Location: { schema: { type: 'string', format: 'uri' } } } }, '429': operationErrors['429'], '503': error('Provider is not enabled'), '500': error('Unexpected server error') },
    } },
    '/api/v1/auth/{provider}/callback': { get: {
      tags: ['Providers'], operationId: 'providerCallback', summary: 'Complete provider authentication',
      description: 'Called by the provider. Requires matching browser state, a single-use server state record, PKCE and a verified provider email. Creates a normal user or signs in an existing provider identity. Matching email alone never links an existing account. Sets the refresh cookie and redirects to WEB_ORIGIN/auth/callback; frontend then POSTs /refresh and GETs /me. No JWT is placed in the redirect URL.',
      security: [], parameters: [
        { name: 'provider', in: 'path', required: true, schema: { type: 'string', enum: ['google', 'github'] } },
        { name: 'code', in: 'query', required: true, schema: { type: 'string', minLength: 1, maxLength: 2048 } },
        { name: 'state', in: 'query', required: true, schema: { type: 'string', pattern: '^[a-f0-9]{64}$' } },
      ], responses: {
        '302': { description: 'Refresh cookie set; redirect to the frontend callback' },
        '400': error('Invalid, expired, reused, or mismatched OAuth state'),
        '401': error('Provider authorization failed'), '403': error('Verified provider email required or account unavailable'),
        '409': error('Email already registered using a different authentication method'),
        '429': operationErrors['429'], '502': error('Provider request failed'), '503': error('Provider is not enabled'), '500': error('Unexpected server error'),
      },
    } },
  };
}

export const authSchemas = {
  RegisterInput: z.toJSONSchema(registrationSchema),
  EmailInput: z.toJSONSchema(emailSchema),
  VerifyEmailInput: z.toJSONSchema(verifyEmailSchema),
  LoginInput: z.toJSONSchema(loginSchema),
  ResetPasswordInput: z.toJSONSchema(resetPasswordSchema),
  OnboardingInput: z.toJSONSchema(onboardingSchema),
  Error: { type: 'object', required: ['message'], properties: {
    message: { type: 'string' },
    errors: { type: 'object', additionalProperties: { type: 'array', items: { type: 'string' } }, description: 'Optional field-level registration validation errors.' },
  } },
  Credentials: { type: 'object', required: ['accessToken', 'tokenType', 'expiresIn'], properties: {
    accessToken: { type: 'string', description: 'Short-lived signed JWT. Keep in memory and send as a Bearer token.' },
    tokenType: { type: 'string', const: 'Bearer' }, expiresIn: { type: 'integer', example: 900 },
  } },
  User: { type: 'object', required: ['id', 'name', 'email', 'username', 'role', 'userType', 'emailVerified', 'onboardingComplete', 'nextStep'], properties: {
    id: { type: 'string', example: '507f1f77bcf86cd799439011' },
    name: { type: 'string', example: 'Jane Doe' }, email: { type: 'string', format: 'email', example: 'jane@example.com' },
    username: { type: ['string', 'null'], example: 'jane_doe' }, role: { type: 'string', enum: Object.values(UserRole), example: UserRole.User },
    userType: { type: ['string', 'null'], enum: [...Object.values(UserType), null] },
    emailVerified: { type: 'boolean', example: true }, onboardingComplete: { type: 'boolean', example: false },
    nextStep: { type: 'string', enum: ['select_user_type', 'dashboard'], example: 'select_user_type' },
  } },
  AccountStatus: { type: 'string', enum: Object.values(AccountStatus) },
};
