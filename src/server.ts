import mongoose from 'mongoose';
import { createRegistrationDependencies } from './features/auth/registration.dependencies.js';
import { reportError } from './shared/logger.js';
import { config } from './config.js';
import { createApp } from './app.js';
import { User } from './features/users/user.model.js';
import { AuthEvent } from './features/auth/auth-event.model.js';
import { Session } from './features/auth/session.model.js';
import { Identity, OAuthState } from './features/auth/oauth.model.js';
import { createAuthRuntime } from './features/auth/auth.runtime.js';

async function main(): Promise<void> {
  await mongoose.connect(config.MONGODB_URI);
  await Promise.all([User.init(), AuthEvent.init(), Session.init(), Identity.init(), OAuthState.init()]);
  const runtime = createAuthRuntime();
  const app = createApp(createRegistrationDependencies(runtime.settings, runtime.sendMail), config.WEB_ORIGIN, runtime);
  const server = app.listen(config.PORT, () => {
    console.info(`Jobdoor API listening on port ${config.PORT}`);
  });
  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.once(signal, () => {
      server.close(() => {
        void mongoose.disconnect().then(() => process.exit(0));
      });
    });
  }
}

main().catch(error => {
  reportError('startup_failed', error);
  process.exit(1);
});

