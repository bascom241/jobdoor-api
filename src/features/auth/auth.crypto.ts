import { createHash, createHmac, randomInt } from 'node:crypto';

export const CODE_LIFETIME_MS = 10 * 60 * 1000;
export const RESEND_COOLDOWN_MS = 30 * 1000;
export const MAX_CODE_ATTEMPTS = 5;
export const hashToken = (value: string): string => createHash('sha256').update(value).digest('hex');
export const generateCode = (): string => randomInt(0, 1_000_000).toString().padStart(6, '0');
export const hashCode = (email: string, code: string, secret: string): string =>
  createHmac('sha256', secret).update(`${email}:${code}`).digest('hex');
