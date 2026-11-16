import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app.js';
import { createRegistrationDependencies } from '../src/features/auth/registration.dependencies.js';
import { User } from '../src/features/users/user.model.js';
import { Session } from '../src/features/auth/session.model.js';
import { AuthEvent } from '../src/features/auth/auth-event.model.js';
import { Identity, OAuthState } from '../src/features/auth/oauth.model.js';
import { hashCode } from '../src/features/auth/auth.crypto.js';
import type { AuthSettings } from '../src/features/auth/auth.types.js';
import { AuthEventType, AuthProvider } from '../src/features/auth/auth.enums.js';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

const settings: AuthSettings = {
  jwtSecret: 'integration-jwt-secret-at-least-32-characters',
  verificationSecret: 'integration-code-secret-at-least-32-characters',
  webOrigin: 'http://localhost:5173', apiUrl: 'http://localhost:3000',
  resetPasswordUrl: 'http://localhost:5173/reset-password', secureCookies: false,
  providers: {},
};
const messages: { email: string; text: string }[] = [];
const sendMail = async (email: string, _subject: string, text: string) => { messages.push({ email, text }); };
const app = createApp(createRegistrationDependencies(settings, sendMail), settings.webOrigin, { settings, sendMail });
const account = { name: 'Jane Doe', email: 'jane@example.com', password: 'Password123!' };
let mongo: MongoMemoryServer;

before(async () => {
  let systemBinary = process.env.MONGOMS_SYSTEM_BINARY;
  if (!systemBinary && process.platform === 'win32') {
    const root = join(process.env.ProgramFiles ?? 'C:/Program Files', 'MongoDB', 'Server');
    if (existsSync(root)) {
      systemBinary = readdirSync(root).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
        .map(version => join(root, version, 'bin', 'mongod.exe')).find(path => existsSync(path));
    }
  }
  const version = systemBinary
    ? execFileSync(systemBinary, ['--version'], { encoding: 'utf8', windowsHide: true }).match(/db version v([\d.]+)/)?.[1]
    : undefined;
  mongo = await MongoMemoryServer.create({ binary: { systemBinary, ...(version ? { version } : {}) } });
  await mongoose.connect(mongo.getUri());
  await Promise.all([User.init(), Session.init(), AuthEvent.init(), Identity.init(), OAuthState.init()]);
});
beforeEach(async () => {
  await Promise.all([User.deleteMany({}), Session.deleteMany({}), AuthEvent.deleteMany({}), Identity.deleteMany({}), OAuthState.deleteMany({})]);
  messages.length = 0;
});
after(async () => { await mongoose.disconnect(); await mongo?.stop(); });

async function registerAndVerify() {
  assert.equal((await request(app).post('/api/v1/auth/register').send(account)).status, 202);
  const code = messages.at(-1)!.text.match(/\b\d{6}\b/)![0];
  assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: account.email, code })).status, 200);
  return code;
}
async function login(persistent = false) {
  const response = await request(app).post('/api/v1/auth/login').send({
    identifier: account.email, password: account.password, keepMeSignedIn: persistent,
  });
  assert.equal(response.status, 200);
  return { access: response.body.accessToken as string, cookie: response.headers['set-cookie'][0].split(';')[0] as string, response };
}

test('registration, verification, login, user-type selection and username login form a complete flow', async () => {
  const code = await registerAndVerify();
  assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: account.email, code })).status, 400);
  const session = await login(true);
  assert.match(session.response.headers['set-cookie'][0], /HttpOnly/);
  assert.match(session.response.headers['set-cookie'][0], /Expires=/);
  const me = await request(app).get('/api/v1/auth/me').auth(session.access, { type: 'bearer' });
  assert.equal(me.body.user.nextStep, 'select_user_type');
  assert.equal(me.body.user.passwordHash, undefined);
  assert.equal(me.body.user.credentialVersion, undefined);
  const onboarding = await request(app).post('/api/v1/auth/onboarding').auth(session.access, { type: 'bearer' })
    .send({ userType: 'job_seeker', username: 'jane_doe' });
  assert.equal(onboarding.status, 200);
  assert.equal(onboarding.body.user.role, 'candidate');
  assert.equal(onboarding.body.user.nextStep, 'dashboard');
  assert.equal((await request(app).post('/api/v1/auth/login').send({ identifier: 'jane_doe', password: account.password })).status, 200);
  assert.equal((await request(app).post('/api/v1/auth/onboarding').auth(session.access, { type: 'bearer' }).send({ userType: 'employer' })).status, 409);
  assert.ok(await AuthEvent.exists({ type: AuthEventType.RegistrationSucceeded }));
  assert.ok(await AuthEvent.exists({ type: AuthEventType.LoginSucceeded }));
});

test('unverified accounts and incorrect passwords cannot sign in', async () => {
  await request(app).post('/api/v1/auth/register').send(account);
  assert.equal((await request(app).post('/api/v1/auth/login').send({ identifier: account.email, password: account.password })).status, 403);
  assert.equal((await request(app).post('/api/v1/auth/login').send({ identifier: account.email, password: 'incorrect' })).status, 401);
  assert.equal((await request(app).get('/api/v1/auth/me')).status, 401);
});

test('verification attempts are capped; resend enforces cooldown and replaces the old code', async () => {
  await request(app).post('/api/v1/auth/register').send(account);
  const original = messages[0].text.match(/\b\d{6}\b/)![0];
  const wrong = original === '000000' ? '111111' : '000000';
  for (let index = 0; index < 5; index++) {
    assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: account.email, code: wrong })).status, 400);
  }
  assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: account.email, code: original })).status, 400);
  await request(app).post('/api/v1/auth/resend-verification').send({ email: account.email });
  assert.equal(messages.length, 1);
  await User.updateOne({ email: account.email }, { verificationRequestedAt: new Date(Date.now() - 31_000) });
  await request(app).post('/api/v1/auth/resend-verification').send({ email: account.email });
  assert.equal(messages.length, 2);
  const code = messages[1].text.match(/\b\d{6}\b/)![0];
  assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: account.email, code })).status, 200);
});

test('expired verification codes do not grant access', async () => {
  await request(app).post('/api/v1/auth/register').send(account);
  const code = messages[0].text.match(/\b\d{6}\b/)![0];
  await User.updateOne({ email: account.email }, { verificationExpiresAt: new Date(Date.now() - 1000) });
  assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: account.email, code })).status, 400);
});

test('refresh tokens rotate, reuse revokes the session, and logout revokes access immediately', async () => {
  await registerAndVerify();
  const session = await login();
  assert.doesNotMatch(session.response.headers['set-cookie'][0], /Expires=/);
  const refreshed = await request(app).post('/api/v1/auth/refresh').set('Cookie', session.cookie).send({});
  assert.equal(refreshed.status, 200);
  assert.notEqual(refreshed.headers['set-cookie'][0].split(';')[0], session.cookie);
  assert.equal((await request(app).post('/api/v1/auth/refresh').set('Cookie', session.cookie).send({})).status, 401);
  assert.equal((await request(app).get('/api/v1/auth/me').auth(refreshed.body.accessToken, { type: 'bearer' })).status, 401);
  const other = await login();
  assert.equal((await request(app).post('/api/v1/auth/logout').set('Cookie', other.cookie).send({})).status, 204);
  assert.equal((await request(app).get('/api/v1/auth/me').auth(other.access, { type: 'bearer' })).status, 401);
});

test('expired or incorrectly signed JWTs and expired sessions cannot grant access', async () => {
  await registerAndVerify();
  const session = await login();
  const claims = jwt.decode(session.access) as jwt.JwtPayload;
  const expired = jwt.sign({ sid: claims.sid }, settings.jwtSecret, {
    subject: claims.sub, issuer: 'jobdoor', audience: 'jobdoor-api', expiresIn: -1,
  });
  const forged = jwt.sign({ sid: claims.sid }, 'different-secret', { subject: claims.sub });
  for (const token of [expired, forged, 'invalid']) {
    assert.equal((await request(app).get('/api/v1/auth/me').auth(token, { type: 'bearer' })).status, 401);
  }
  await Session.updateMany({}, { expiresAt: new Date(Date.now() - 1000) });
  assert.equal((await request(app).get('/api/v1/auth/me').auth(session.access, { type: 'bearer' })).status, 401);
});

test('password recovery is single-use and invalidates every existing session', async () => {
  await registerAndVerify();
  const session = await login();
  const missing = await request(app).post('/api/v1/auth/forgot-password').send({ email: 'nobody@example.com' });
  const existing = await request(app).post('/api/v1/auth/forgot-password').send({ email: account.email });
  assert.deepEqual(missing.body, existing.body);
  const token = new URL(messages.at(-1)!.text.split(': ').at(-1)!).searchParams.get('token');
  assert.ok(token);
  const reset = { token, password: 'NewPassword123!' };
  assert.equal((await request(app).post('/api/v1/auth/reset-password').send(reset)).status, 200);
  assert.equal((await request(app).post('/api/v1/auth/reset-password').send(reset)).status, 400);
  assert.equal((await request(app).get('/api/v1/auth/me').auth(session.access, { type: 'bearer' })).status, 401);
  assert.equal((await request(app).post('/api/v1/auth/refresh').set('Cookie', session.cookie).send({})).status, 401);
  assert.equal((await request(app).post('/api/v1/auth/login').send({ identifier: account.email, password: account.password })).status, 401);
  assert.equal((await request(app).post('/api/v1/auth/login').send({ identifier: account.email, password: reset.password })).status, 200);
});

test('onboarding cannot grant HR privileges and rejects injected role fields', async () => {
  await registerAndVerify();
  const session = await login();
  assert.equal((await request(app).post('/api/v1/auth/onboarding').auth(session.access, { type: 'bearer' })
    .send({ userType: 'manager_hr_admin', role: 'admin' })).status, 400);
  const response = await request(app).post('/api/v1/auth/onboarding').auth(session.access, { type: 'bearer' })
    .send({ userType: 'manager_hr_admin' });
  assert.equal(response.status, 200);
  assert.equal(response.body.user.role, 'user');
});

test('cookie mutations reject untrusted origins and disabled providers are explicit', async () => {
  assert.equal((await request(app).post('/api/v1/auth/refresh').set('Origin', 'https://attacker.example').send({})).status, 403);
  assert.equal((await request(app).post('/api/v1/auth/refresh').type('form').send({})).status, 415);
  assert.deepEqual((await request(app).get('/api/v1/auth/providers')).body.providers, []);
  assert.equal((await request(app).get('/api/v1/auth/google')).status, 503);
  assert.equal((await request(app).get('/api/v1/auth/google/callback?code=test&state=' + 'a'.repeat(64))).status, 400);
});

test('concurrent verification consumes a code only once', async () => {
  await request(app).post('/api/v1/auth/register').send(account);
  const code = messages[0].text.match(/\b\d{6}\b/)![0];
  assert.equal((await User.findOne({ email: account.email }).select('+verificationTokenHash'))!.verificationTokenHash,
    hashCode(account.email, code, settings.verificationSecret));
  const results = await Promise.all([0, 1].map(() => request(app).post('/api/v1/auth/verify-email').send({ email: account.email, code })));
  assert.deepEqual(results.map(result => result.status).sort(), [200, 400]);
});

test('Google OAuth uses PKCE, creates a verified normal user, and rejects state replay', async context => {
  const providerSettings: AuthSettings = { ...settings, providers: { google: { clientId: 'test-client', clientSecret: 'test-secret' } } };
  const providerApp = createApp(createRegistrationDependencies(providerSettings, sendMail), settings.webOrigin,
    { settings: providerSettings, sendMail });
  context.mock.method(globalThis, 'fetch', async (url: string, init: RequestInit) => {
    if (url.includes('token')) {
      const body = init.body as URLSearchParams;
      assert.ok(body.get('code_verifier'));
      assert.equal(body.get('client_id'), 'test-client');
      return Response.json({ access_token: 'provider-access-token' });
    }
    return Response.json({ sub: 'google-user-123', email: 'google@example.com', email_verified: true, name: 'Google User' });
  });
  const start = await request(providerApp).get('/api/v1/auth/google');
  assert.equal(start.status, 302);
  const url = new URL(start.headers.location);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  const state = url.searchParams.get('state')!;
  const cookie = start.headers['set-cookie'][0].split(';')[0];
  const path = `/api/v1/auth/google/callback?code=valid-code&state=${state}`;
  const callback = await request(providerApp).get(path).set('Cookie', cookie);
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.location, `${settings.webOrigin}/auth/callback`);
  const user = await User.findOne({ email: 'google@example.com' });
  assert.equal(user?.role, 'user');
  assert.ok(user?.emailVerifiedAt);
  assert.equal(await Identity.countDocuments({ provider: AuthProvider.Google }), 1);
  assert.equal((await request(providerApp).get(path).set('Cookie', cookie)).status, 400);
});

test('OAuth never silently links a matching email to an existing account', async context => {
  await User.create({ name: 'Existing User', email: 'existing@example.com' });
  const providerSettings: AuthSettings = { ...settings, providers: { github: { clientId: 'test-client', clientSecret: 'test-secret' } } };
  const providerApp = createApp(createRegistrationDependencies(providerSettings, sendMail), settings.webOrigin,
    { settings: providerSettings, sendMail });
  context.mock.method(globalThis, 'fetch', async (url: string) => {
    if (url.includes('access_token')) return Response.json({ access_token: 'test-provider-token' });
    if (url.endsWith('/emails')) return Response.json([{ email: 'existing@example.com', primary: true, verified: true }]);
    return Response.json({ id: 123, login: 'existing-user', name: 'Existing User' });
  });
  const start = await request(providerApp).get('/api/v1/auth/github');
  const state = new URL(start.headers.location).searchParams.get('state')!;
  const response = await request(providerApp).get(`/api/v1/auth/github/callback?code=valid-code&state=${state}`)
    .set('Cookie', start.headers['set-cookie'][0].split(';')[0]);
  assert.equal(response.status, 409);
  assert.equal(await Identity.countDocuments({}), 0);
  assert.equal(await Session.countDocuments({}), 0);
});
