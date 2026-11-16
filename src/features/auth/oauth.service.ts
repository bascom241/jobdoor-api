import { createHash, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { HttpError } from '../../shared/http-error.js';
import { User } from '../users/user.model.js';
import { AccountStatus } from '../users/user.enums.js';
import { AuthEvent } from './auth-event.model.js';
import { AuthEventType, AuthProvider } from './auth.enums.js';
import { hashToken } from './auth.crypto.js';
import { Identity, OAuthState } from './oauth.model.js';
import type { AuthSettings } from './auth.types.js';
import type { AuthService } from './auth.service.js';

const endpoints = {
  [AuthProvider.Google]: {
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token', scope: 'openid email profile',
  },
  [AuthProvider.GitHub]: {
    authorize: 'https://github.com/login/oauth/authorize',
    token: 'https://github.com/login/oauth/access_token', scope: 'read:user user:email',
  },
};

export class OAuthService {
  constructor(private readonly settings: AuthSettings, private readonly auth: AuthService) {}

  private providerConfig(provider: AuthProvider) {
    const credentials = this.settings.providers[provider];
    if (!credentials) throw new HttpError(503, 'Authentication provider is not enabled');
    return { ...endpoints[provider], ...credentials,
      redirectUri: `${this.settings.apiUrl}/api/v1/auth/${provider}/callback` };
  }

  async start(provider: AuthProvider) {
    const config = this.providerConfig(provider);
    const state = randomBytes(32).toString('hex');
    const verifier = randomBytes(32).toString('base64url');
    await OAuthState.create({
      stateHash: hashToken(state), provider, verifier, expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });
    const url = new URL(config.authorize);
    url.search = new URLSearchParams({
      client_id: config.clientId, redirect_uri: config.redirectUri,
      response_type: 'code', scope: config.scope, state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    }).toString();
    return { state, url: url.toString() };
  }

  private async json(url: string, init: RequestInit = {}): Promise<unknown> {
    const response = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
    if (!response.ok) throw new HttpError(502, 'Authentication provider request failed');
    return response.json();
  }

  async callback(provider: AuthProvider, code: string, state: string) {
    const config = this.providerConfig(provider);
    const request = await OAuthState.findOneAndDelete({
      stateHash: hashToken(state), provider, expiresAt: { $gt: new Date() },
    }).select('+verifier');
    if (!request) throw new HttpError(400, 'Invalid or expired authentication request');
    const token = z.object({ access_token: z.string().min(1) }).safeParse(await this.json(config.token, {
      method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: config.clientId, client_secret: config.clientSecret,
        code, redirect_uri: config.redirectUri, grant_type: 'authorization_code', code_verifier: request.verifier,
      }),
    }));
    if (!token.success) throw new HttpError(401, 'Provider authorization failed');
    const headers = { Authorization: `Bearer ${token.data.access_token}`, Accept: 'application/json', 'User-Agent': 'Jobdoor' };
    let profile: { subject: string; email: string; name: string };
    if (provider === AuthProvider.Google) {
      const data = z.object({ sub: z.string().min(1), email: z.email(), email_verified: z.literal(true), name: z.string().optional() })
        .safeParse(await this.json('https://openidconnect.googleapis.com/v1/userinfo', { headers }));
      if (!data.success) throw new HttpError(403, 'A verified provider email is required');
      profile = { subject: data.data.sub, email: data.data.email.toLowerCase(), name: data.data.name ?? data.data.email };
    } else {
      const data = z.object({ id: z.number().int(), login: z.string(), name: z.string().nullable().optional() })
        .parse(await this.json('https://api.github.com/user', { headers }));
      const emails = z.array(z.object({ email: z.email(), primary: z.boolean(), verified: z.boolean() }))
        .parse(await this.json('https://api.github.com/user/emails', { headers }));
      const email = emails.find(item => item.primary && item.verified);
      if (!email) throw new HttpError(403, 'A verified primary provider email is required');
      profile = { subject: data.id.toString(), email: email.email.toLowerCase(), name: data.name ?? data.login };
    }
    const identity = await Identity.findOne({ provider, subject: profile.subject });
    if (identity) {
      const user = await User.findById(identity.userId).select('+credentialVersion');
      if (!user || user.status !== AccountStatus.Active || !user.emailVerifiedAt) throw new HttpError(403, 'Account is unavailable');
      return this.auth.createSession(user);
    }
    // Never silently attach a provider to an existing password account based on email alone.
    if (await User.exists({ email: profile.email })) {
      throw new HttpError(409, 'An account already exists for this email. Sign in with its existing method.');
    }
    let user;
    try {
      user = await User.create({
        name: profile.name.slice(0, 100), email: profile.email,
        status: AccountStatus.Active, emailVerifiedAt: new Date(),
      });
    } catch (error) {
      if (typeof error === 'object' && error && 'code' in error && error.code === 11000) {
        throw new HttpError(409, 'An account already exists for this email');
      }
      throw error;
    }
    try {
      await Identity.create({ provider, subject: profile.subject, userId: user._id });
    } catch (error) {
      await User.deleteOne({ _id: user._id });
      throw error;
    }
    await AuthEvent.create({ userId: user._id, type: AuthEventType.RegistrationSucceeded });
    return this.auth.createSession(user);
  }
}
