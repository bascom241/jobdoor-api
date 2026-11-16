import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';
import { HttpError } from '../../shared/http-error.js';
import { AuthService } from './auth.service.js';
import { OAuthService } from './oauth.service.js';
import { AuthProvider } from './auth.enums.js';
import { emailSchema, loginSchema, onboardingSchema, resetPasswordSchema, verifyEmailSchema } from './auth.schemas.js';
import { bearerToken, cookieOptions, readCookie, REFRESH_COOKIE, setSessionCookie, STATE_COOKIE } from './session.http.js';
import type { AuthSettings, SendMail } from './auth.types.js';

export function createSessionRouter(settings: AuthSettings, sendMail: SendMail) {
  const router = Router();
  const auth = new AuthService(settings, sendMail);
  const oauth = new OAuthService(settings, auth);
  const limit = (count: number) => rateLimit({ windowMs: 15 * 60 * 1000, limit: count, standardHeaders: 'draft-8', legacyHeaders: false });
  const parse = <T>(schema: z.ZodType<T>, req: Request): T => {
    const result = schema.safeParse(req.body);
    if (!result.success) throw new HttpError(400, 'Invalid request input');
    return result.data;
  };
  const respondSession = (res: Response, credentials: Awaited<ReturnType<AuthService['refresh']>>) => {
    setSessionCookie(res, credentials, settings.secureCookies);
    res.json({ accessToken: credentials.accessToken, tokenType: 'Bearer', expiresIn: credentials.expiresIn });
  };
  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
  router.use((req, _res, next) => {
    // JSON POSTs plus exact Origin checks protect cookie-authenticated mutations.
    if (req.method === 'POST') {
      if (req.headers.origin && req.headers.origin !== settings.webOrigin) throw new HttpError(403, 'Origin is not allowed');
      if (!req.is('application/json')) throw new HttpError(415, 'Content-Type must be application/json');
      if (req.headers['sec-fetch-site'] === 'cross-site') throw new HttpError(403, 'Cross-site requests are not allowed');
    }
    next();
  });
  router.post('/verify-email', limit(20), async (req, res) => {
    const input = parse(verifyEmailSchema, req);
    await auth.verifyEmail(input.email, input.code);
    res.json({ message: 'Email verified. You can now sign in.' });
  });
  router.post('/resend-verification', limit(10), async (req, res) => {
    await auth.resendVerification(parse(emailSchema, req).email);
    res.status(202).json({ message: 'If eligible, a verification code will be sent.', resendAfterSeconds: 30 });
  });
  router.post('/login', limit(20), async (req, res) => {
    const input = parse(loginSchema, req);
    respondSession(res, await auth.login(input.identifier, input.password, input.keepMeSignedIn));
  });
  router.post('/refresh', limit(100), async (req, res) => {
    const token = readCookie(req, REFRESH_COOKIE);
    if (!token || !/^[a-f0-9]{64}$/.test(token)) throw new HttpError(401, 'Invalid or expired credentials');
    try { respondSession(res, await auth.refresh(token)); }
    catch (error) { res.clearCookie(REFRESH_COOKIE, cookieOptions(settings.secureCookies)); throw error; }
  });
  router.post('/logout', async (req, res) => {
    const token = readCookie(req, REFRESH_COOKIE);
    if (token) await auth.logout(token);
    res.clearCookie(REFRESH_COOKIE, cookieOptions(settings.secureCookies));
    res.status(204).end();
  });
  router.post('/forgot-password', limit(10), async (req, res) => {
    await auth.forgotPassword(parse(emailSchema, req).email);
    res.status(202).json({ message: 'If eligible, password reset instructions will be sent.' });
  });
  router.post('/reset-password', limit(20), async (req, res) => {
    const input = parse(resetPasswordSchema, req);
    await auth.resetPassword(input.token, input.password);
    res.clearCookie(REFRESH_COOKIE, cookieOptions(settings.secureCookies));
    res.json({ message: 'Password reset. Sign in with your new password.' });
  });
  router.get('/me', async (req, res) => {
    const { user } = await auth.authenticate(bearerToken(req));
    res.json({ user: auth.publicUser(user) });
  });
  router.post('/onboarding', async (req, res) => {
    const { user } = await auth.authenticate(bearerToken(req));
    const input = parse(onboardingSchema, req);
    res.json({ user: await auth.onboard(user._id, input.userType, input.username) });
  });
  router.get('/providers', (_req, res) => {
    res.json({ providers: Object.values(AuthProvider).filter(provider => Boolean(settings.providers[provider])) });
  });
  router.get('/:provider/callback', limit(30), async (req, res) => {
    const provider = z.enum(AuthProvider).safeParse(req.params.provider);
    const input = z.object({ code: z.string().min(1).max(2048), state: z.string().regex(/^[a-f0-9]{64}$/) }).safeParse(req.query);
    const state = readCookie(req, STATE_COOKIE);
    res.clearCookie(STATE_COOKIE, cookieOptions(settings.secureCookies));
    if (!provider.success || !input.success || !state || state !== input.data.state) throw new HttpError(400, 'Invalid provider callback');
    const credentials = await oauth.callback(provider.data, input.data.code, state);
    setSessionCookie(res, credentials, settings.secureCookies);
    // No access or refresh credentials in browser URLs; frontend calls /refresh.
    res.redirect(`${settings.webOrigin}/auth/callback`);
  });
  router.get('/:provider', limit(30), async (req, res, next) => {
    const provider = z.enum(AuthProvider).safeParse(req.params.provider);
    if (!provider.success) { next(); return; }
    const result = await oauth.start(provider.data);
    res.cookie(STATE_COOKIE, result.state, { ...cookieOptions(settings.secureCookies), maxAge: 10 * 60 * 1000 });
    res.redirect(result.url);
  });
  return router;
}
