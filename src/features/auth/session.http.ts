import type { Request, Response, CookieOptions } from 'express';
import { HttpError } from '../../shared/http-error.js';

export const REFRESH_COOKIE = 'jobdoor_refresh';
export const STATE_COOKIE = 'jobdoor_oauth_state';

export function readCookie(req: Request, name: string): string | undefined {
  const values = (req.headers.cookie ?? '').split(';').map(value => value.trim());
  const value = values.find(value => value.startsWith(`${name}=`))?.slice(name.length + 1);
  if (!value) return undefined;
  try { return decodeURIComponent(value); } catch { return undefined; }
}

export function cookieOptions(secure: boolean): CookieOptions {
  return { httpOnly: true, secure, sameSite: 'lax', path: '/api/v1/auth' };
}

export function bearerToken(req: Request): string {
  const match = /^Bearer ([^ ]+)$/i.exec(req.headers.authorization ?? '');
  if (!match) throw new HttpError(401, 'Authentication is required');
  return match[1];
}

export function setSessionCookie(res: Response, credentials: { refreshToken: string; persistent: boolean; expiresAt: Date }, secure: boolean): void {
  res.cookie(REFRESH_COOKIE, credentials.refreshToken, {
    ...cookieOptions(secure),
    ...(credentials.persistent ? { expires: credentials.expiresAt } : {}),
  });
}
