import assert from 'node:assert/strict';
import { test } from 'node:test';
import bcrypt from 'bcryptjs';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { AccountStatus, UserRole } from '../src/features/users/user.enums.js';
import type { RegistrationDependencies } from '../src/features/auth/registration.service.js';
import { hashCode } from '../src/features/auth/auth.crypto.js';

function setup(overrides: Partial<RegistrationDependencies> = {}) {
  const users: Parameters<RegistrationDependencies['createUser']>[0][] = [];
  const messages: string[] = [];
  const events: string[] = [];
  const deps: RegistrationDependencies = {
    verificationSecret: 'test-verification-secret-at-least-32-chars',
    createUser: async data => { users.push(data); return { id: 'user-id' }; },
    recordEvent: async (_id, type) => { events.push(type); },
    sendVerification: async (_email, token) => { messages.push(token); },
    markEmailSent: async () => {},
    reportError: () => {},
    ...overrides,
  };
  return { app: createApp(deps, 'http://localhost:5173'), users, messages, events };
}
const input = { name: 'Jane Doe', email: 'JANE@example.com', password: 'a secure passphrase' };

test('registration stores a hashed password and token, creates an unverified normal user, and records the event', async () => {
  const { app, users, messages, events } = setup();
  const response = await request(app).post('/api/v1/auth/register').send(input);
  assert.equal(response.status, 202);
  assert.equal(users[0].email, 'jane@example.com');
  assert.equal(users[0].role, UserRole.User);
  assert.equal(users[0].status, AccountStatus.PendingVerification);
  assert.ok(await bcrypt.compare(input.password, users[0].passwordHash));
  assert.match(messages[0], /^\d{6}$/);
  assert.equal(users[0].verificationTokenHash, hashCode(users[0].email, messages[0], 'test-verification-secret-at-least-32-chars'));
  assert.equal(events.length, 1);
  assert.ok(!JSON.stringify(response.body).includes(messages[0]));
  assert.ok(!JSON.stringify(response.body).includes(users[0].passwordHash));
});

test('invalid data, role injection, and passwords exceeding bcrypt byte limits are rejected', async () => {
  const { app, users } = setup();
  for (const payload of [ { ...input, email: 'invalid' }, { ...input, password: 'short' },
    { ...input, role: 'candidate' }, { ...input, password: '😀'.repeat(20) } ]) {
    assert.equal((await request(app).post('/api/v1/auth/register').send(payload)).status, 400);
  }
  assert.equal(users.length, 0);
});

test('duplicate registrations return the same response without sending another email', async () => {
  const normal = setup();
  const duplicate = setup({ createUser: async () => { throw { code: 11000 }; } });
  const first = await request(normal.app).post('/api/v1/auth/register').send(input);
  const second = await request(duplicate.app).post('/api/v1/auth/register').send(input);
  assert.equal(second.status, first.status);
  assert.deepEqual(second.body, first.body);
  assert.equal(duplicate.messages.length, 0);
});

test('database failures return a generic error', async () => {
  const { app } = setup({ createUser: async () => { throw new Error('secret database details'); } });
  const response = await request(app).post('/api/v1/auth/register').send(input);
  assert.equal(response.status, 500);
  assert.ok(!JSON.stringify(response.body).includes('secret'));
});
