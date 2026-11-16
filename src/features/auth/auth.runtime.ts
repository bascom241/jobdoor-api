import nodemailer from 'nodemailer';
import { config } from '../../config.js';
import type { AuthSettings, SendMail } from './auth.types.js';

export function createAuthRuntime(): { settings: AuthSettings; sendMail: SendMail } {
  const transport = nodemailer.createTransport({
    host: config.SMTP_HOST, port: config.SMTP_PORT, secure: config.SMTP_SECURE,
    ...(config.SMTP_USER ? { auth: { user: config.SMTP_USER, pass: config.SMTP_PASSWORD } } : {}),
  });
  return {
    settings: {
      jwtSecret: config.JWT_SECRET, verificationSecret: config.VERIFICATION_SECRET,
      webOrigin: config.WEB_ORIGIN, apiUrl: config.API_URL,
      resetPasswordUrl: config.RESET_PASSWORD_URL, secureCookies: config.NODE_ENV === 'production',
      providers: {
        ...(config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET ? {
          google: { clientId: config.GOOGLE_CLIENT_ID, clientSecret: config.GOOGLE_CLIENT_SECRET },
        } : {}),
        ...(config.GITHUB_CLIENT_ID && config.GITHUB_CLIENT_SECRET ? {
          github: { clientId: config.GITHUB_CLIENT_ID, clientSecret: config.GITHUB_CLIENT_SECRET },
        } : {}),
      },
    },
    sendMail: async (email, subject, text) => {
      await transport.sendMail({ from: config.EMAIL_FROM, to: email, subject, text });
    },
  };
}
