import { randomBytes } from 'node:crypto';
import { Router } from 'express';
import helmet from 'helmet';
import { apiReference } from '@scalar/express-api-reference';
import { createOpenApiDocument } from './openapi.js';

export function createDocsRouter(includeSessionRoutes: boolean) {
  const router = Router();
  const document = createOpenApiDocument(includeSessionRoutes);

  router.get('/openapi.json', (_req, res) => { res.json(document); });
  router.get<never>('/docs', (req, res, next) => {
    const nonce = randomBytes(16).toString('base64');
    const policy = helmet.contentSecurityPolicy({ directives: {
      scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', `'nonce-${nonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'data:'],
      workerSrc: ["'self'", 'blob:'],
      upgradeInsecureRequests: null,
    } });
    policy(req, res, () => {
      apiReference({
        url: '/api/openapi.json',
        pageTitle: 'Jobdoor API Reference',
        theme: 'default',
        nonce,
        withDefaultFonts: false,
        persistAuth: false,
        proxyUrl: '',
      })(req, res, next);
    });
  });

  return router;
}
