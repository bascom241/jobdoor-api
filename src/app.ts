import express, { type ErrorRequestHandler } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import type { RegistrationDependencies } from './features/auth/registration.service.js';
import { createAuthRouter } from './features/auth/auth.routes.js';
import { createSessionRouter } from './features/auth/session.routes.js';
import type { AuthSettings, SendMail } from './features/auth/auth.types.js';
import { HttpError } from './shared/http-error.js';

export function createApp(deps: RegistrationDependencies, webOrigin: string, auth?: { settings: AuthSettings; sendMail: SendMail }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(cors({ origin: webOrigin, credentials: true }));
  app.use(express.json({ limit: '16kb' }));
  app.use('/api/v1/auth', createAuthRouter(deps));
  if (auth) app.use('/api/v1/auth', createSessionRouter(auth.settings, auth.sendMail));
  app.use((_req, res) => { res.status(404).json({ message: 'Route not found' }); });
  const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
    if (error instanceof HttpError) {
      res.status(error.status).json({ message: error.message });
      return;
    }
    if (error instanceof SyntaxError && 'body' in error) {
      res.status(400).json({ message: 'Invalid JSON body' });
      return;
    }
    if (error?.type === 'entity.too.large') {
      res.status(413).json({ message: 'Request body too large' });
      return;
    }
    deps.reportError('request_failed', error);
    res.status(500).json({ message: 'An unexpected error occurred' });
  };
  app.use(errorHandler);
  return app;
}
