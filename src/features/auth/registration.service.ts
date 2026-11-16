import bcrypt from 'bcryptjs';
import type { RegistrationInput } from './registration.schema.js';
import { AccountStatus, UserRole } from '../users/user.enums.js';
import { AuthEventType } from './auth.enums.js';
import { CODE_LIFETIME_MS, generateCode, hashCode } from './auth.crypto.js';

const PASSWORD_HASH_COST = 12;
export interface RegistrationDependencies {
  verificationSecret: string;
  createUser: (data: {
    name: string;
    email: string;
    passwordHash: string;
    role: UserRole;
    status: AccountStatus;
    verificationTokenHash: string;
    verificationExpiresAt: Date;
  }) => Promise<{ id: string }>;
  recordEvent: (userId: string, type: AuthEventType) => Promise<void>;
  sendVerification: (email: string, token: string) => Promise<void>;
  markEmailSent: (userId: string) => Promise<void>;
  reportError: (operation: string, error: unknown) => void;
}

export async function register(input: RegistrationInput, deps: RegistrationDependencies): Promise<void> {
  const token = generateCode();
  const passwordHash = await bcrypt.hash(input.password, PASSWORD_HASH_COST);
  let user: { id: string };
  try {
    user = await deps.createUser({
      name: input.name,
      email: input.email,
      passwordHash,
      role: UserRole.User,
      status: AccountStatus.PendingVerification,
      verificationTokenHash: hashCode(input.email, token, deps.verificationSecret),
      verificationExpiresAt: new Date(Date.now() + CODE_LIFETIME_MS),
    });
  } catch (error) {
    // The unique email index handles simultaneous registrations safely.
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 11000) return;
    throw error;
  }
  await deps.recordEvent(user.id, AuthEventType.RegistrationSucceeded);
  try {
    await deps.sendVerification(input.email, token);
    await deps.markEmailSent(user.id);
  } catch (error) {
    deps.reportError('verification_email_delivery_failed', error);
  }
}
