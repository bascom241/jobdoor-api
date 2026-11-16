import { reportError } from '../../shared/logger.js';
import { User } from '../users/user.model.js';
import { AuthEvent } from './auth-event.model.js';
import type { RegistrationDependencies } from './registration.service.js';
import type { AuthSettings, SendMail } from './auth.types.js';

export function createRegistrationDependencies(settings: AuthSettings, sendMail: SendMail): RegistrationDependencies {
  return {
    verificationSecret: settings.verificationSecret,
    createUser: async data => {
      const user = await User.create(data);
      return { id: user.id };
    },
    recordEvent: async (userId, type) => {
      await AuthEvent.create({ userId, type });
    },
    sendVerification: async (email, token) => {
      await sendMail(email, 'Verify your Jobdoor email', `Your verification code is ${token}. It expires in 10 minutes.`);
    },
    markEmailSent: async userId => {
      await User.updateOne({ _id: userId }, { verificationEmailSentAt: new Date() });
    },
    reportError,
  };
}

