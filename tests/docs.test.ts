import assert from 'node:assert/strict';
import { test } from 'node:test';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createOpenApiDocument } from '../src/docs/openapi.js';
import type { RegistrationDependencies } from '../src/features/auth/registration.service.js';

const deps: RegistrationDependencies = {
  verificationSecret: 'docs-test-secret-at-least-32-characters',
  createUser: async () => { throw new Error('Documentation must not access the database'); },
  recordEvent: async () => {}, sendVerification: async () => {}, markEmailSent: async () => {},
  reportError: () => {},
};
const app = createApp(deps, 'http://localhost:5173', {
  settings: {
    jwtSecret: 'docs-test-jwt-secret-at-least-32-characters',
    verificationSecret: deps.verificationSecret,
    webOrigin: 'http://localhost:5173', apiUrl: 'http://localhost:3000',
    resetPasswordUrl: 'http://localhost:5173/reset-password', secureCookies: false, providers: {},
  },
  sendMail: async () => {},
});

test('Scalar is served with a per-request nonce allowed by its scoped CSP', async () => {
  const first = await request(app).get('/api/docs');
  const second = await request(app).get('/api/docs');
  assert.equal(first.status, 200);
  assert.match(first.headers['content-type'], /text\/html/);
  assert.match(first.text, /Jobdoor API Reference/);
  assert.match(first.text, /\/api\/openapi.json/);
  assert.match(first.text, /cdn.jsdelivr.net/);
  const nonce = first.text.match(/nonce="([^"]+)"/)![1];
  assert.ok(first.headers['content-security-policy'].includes(`'nonce-${nonce}'`));
  assert.notEqual(first.headers['content-security-policy'], second.headers['content-security-policy']);
  const other = await request(app).get('/api/v1/auth/providers');
  assert.ok(!other.headers['content-security-policy'].includes('cdn.jsdelivr.net'));
});

test('OpenAPI documents current endpoints, validation schemas and authentication schemes', async () => {
  const response = await request(app).get('/api/openapi.json');
  assert.equal(response.status, 200);
  const document = response.body;
  assert.equal(document.openapi, '3.1.0');
  assert.equal(document.components.schemas.RegisterInput.properties.password.minLength, 8);
  assert.equal(document.components.schemas.RegisterInput.additionalProperties, false);
  assert.deepEqual(document.paths['/api/v1/auth/me'].get.security, [{ bearerAuth: [] }]);
  assert.equal(document.components.securitySchemes.refreshCookie.in, 'cookie');
  const operationIds = new Set<string>();
  for (const item of Object.values(document.paths) as Record<string, { operationId: string; responses: object }>[]) {
    for (const operation of Object.values(item)) {
      assert.ok(operation.operationId);
      assert.ok(!operationIds.has(operation.operationId));
      operationIds.add(operation.operationId);
      assert.ok(operation.responses);
    }
  }
  assert.equal(operationIds.size, 13);
  function checkReferences(value: unknown): void {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if (key === '$ref') {
        const name = String(child).replace('#/components/schemas/', '');
        assert.ok(name in document.components.schemas, `Missing schema ${name}`);
      } else checkReferences(child);
    }
  }
  checkReferences(document);
});

test('registration-only app documents only its enabled registration endpoint', () => {
  const document = createOpenApiDocument(false);
  assert.deepEqual(Object.keys(document.paths), ['/api/v1/auth/register']);
});
