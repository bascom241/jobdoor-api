import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Types } from 'mongoose';
import { User } from '../users/user.model.js';
import { AccountStatus, UserRole, UserType } from '../users/user.enums.js';
import { HttpError } from '../../shared/http-error.js';
import { AuthEvent } from './auth-event.model.js';
import { AuthEventType } from './auth.enums.js';
import { Session } from './session.model.js';
import { CODE_LIFETIME_MS, MAX_CODE_ATTEMPTS, RESEND_COOLDOWN_MS, generateCode, hashCode, hashToken } from './auth.crypto.js';
import type { AuthSettings, SendMail } from './auth.types.js';
import { reportError } from '../../shared/logger.js';

const ACCESS_LIFETIME_SECONDS = 15 * 60;
const SESSION_LIFETIME_MS = 24 * 60 * 60 * 1000;
const PERSISTENT_LIFETIME_MS = 30 * SESSION_LIFETIME_MS;
const RESET_LIFETIME_MS = 30 * 60 * 1000;
const invalidCredentials = () => new HttpError(401, 'Invalid or expired credentials');
const dummyHash = bcrypt.hashSync(randomBytes(32).toString('hex'), 12);

export class AuthService {
  constructor(private readonly settings: AuthSettings, private readonly sendMail: SendMail) {}

  private async event(userId: Types.ObjectId, type: AuthEventType): Promise<void> {
    await AuthEvent.create({ userId, type });
  }

  async verifyEmail(email: string, code: string): Promise<void> {
    const tokenHash = hashCode(email, code, this.settings.verificationSecret);
    const user = await User.findOneAndUpdate({
      email, status: AccountStatus.PendingVerification,
      verificationTokenHash: tokenHash,
      verificationExpiresAt: { $gt: new Date() },
      verificationAttempts: { $lt: MAX_CODE_ATTEMPTS },
    }, {
      $set: { status: AccountStatus.Active, emailVerifiedAt: new Date() },
      $unset: { verificationTokenHash: 1, verificationExpiresAt: 1 },
    }, { returnDocument: 'after' });
    if (!user) {
      await User.updateOne({
        email, status: AccountStatus.PendingVerification,
        verificationTokenHash: { $ne: tokenHash },
        verificationExpiresAt: { $gt: new Date() },
        verificationAttempts: { $lt: MAX_CODE_ATTEMPTS },
      }, { $inc: { verificationAttempts: 1 } });
      throw new HttpError(400, 'Invalid or expired verification code');
    }
    await this.event(user._id, AuthEventType.EmailVerified);
  }

  async resendVerification(email: string): Promise<void> {
    const code = generateCode();
    const user = await User.findOneAndUpdate({
      email, status: AccountStatus.PendingVerification,
      verificationRequestedAt: { $lte: new Date(Date.now() - RESEND_COOLDOWN_MS) },
    }, { $set: {
      verificationTokenHash: hashCode(email, code, this.settings.verificationSecret),
      verificationExpiresAt: new Date(Date.now() + CODE_LIFETIME_MS),
      verificationRequestedAt: new Date(), verificationAttempts: 0,
      verificationEmailSentAt: null,
    } });
    if (!user) return;
    try {
      await this.sendMail(email, 'Verify your Jobdoor email', `Your verification code is ${code}. It expires in 10 minutes.`);
      await User.updateOne({ _id: user._id }, { verificationEmailSentAt: new Date() });
    } catch (error) { reportError('verification_email_delivery_failed', error); }
  }

  async login(identifier: string, password: string, persistent: boolean) {
    const user = await User.findOne({ $or: [{ email: identifier }, { username: identifier }] })
      .select('+passwordHash +credentialVersion');
    const passwordMatches = await bcrypt.compare(password, user?.passwordHash ?? dummyHash);
    if (!user || !user.passwordHash || !passwordMatches) throw invalidCredentials();
    if (user.status !== AccountStatus.Active || !user.emailVerifiedAt) {
      throw new HttpError(403, 'Verify your email before signing in');
    }
    return this.createSession(user, persistent);
  }

  async createSession(user: { _id: Types.ObjectId; credentialVersion?: number }, persistent = false) {
    const refreshToken = randomBytes(32).toString('hex');
    const session = await Session.create({
      userId: user._id, refreshHash: hashToken(refreshToken), persistent,
      credentialVersion: user.credentialVersion ?? 0,
      expiresAt: new Date(Date.now() + (persistent ? PERSISTENT_LIFETIME_MS : SESSION_LIFETIME_MS)),
    });
    await this.event(user._id, AuthEventType.LoginSucceeded);
    return this.credentials(session, refreshToken);
  }

  private credentials(session: { id: string; userId: Types.ObjectId; persistent: boolean; expiresAt: Date }, refreshToken: string) {
    return {
      accessToken: jwt.sign({ sid: session.id }, this.settings.jwtSecret, {
        algorithm: 'HS256', subject: session.userId.toString(),
        issuer: 'jobdoor', audience: 'jobdoor-api', expiresIn: ACCESS_LIFETIME_SECONDS,
      }),
      expiresIn: ACCESS_LIFETIME_SECONDS,
      refreshToken, persistent: session.persistent, expiresAt: session.expiresAt,
    };
  }

  async refresh(token: string) {
    const oldHash = hashToken(token);
    const newToken = randomBytes(32).toString('hex');
    const session = await Session.findOneAndUpdate({
      refreshHash: oldHash, revokedAt: null, expiresAt: { $gt: new Date() },
    }, {
      $set: { refreshHash: hashToken(newToken) },
      $push: { previousRefreshHashes: oldHash },
    }, { returnDocument: 'after' });
    if (!session) {
      // Reusing a rotated refresh token invalidates its entire session.
      await Session.updateOne({ previousRefreshHashes: oldHash, revokedAt: null }, { revokedAt: new Date() });
      throw invalidCredentials();
    }
    const user = await User.findById(session.userId).select('+credentialVersion');
    if (!user || user.status !== AccountStatus.Active || !user.emailVerifiedAt || user.credentialVersion !== session.credentialVersion) {
      await Session.updateOne({ _id: session._id }, { revokedAt: new Date() });
      throw invalidCredentials();
    }
    return this.credentials(session, newToken);
  }

  async authenticate(token: string) {
    let payload: jwt.JwtPayload;
    try {
      const decoded = jwt.verify(token, this.settings.jwtSecret, {
        algorithms: ['HS256'], issuer: 'jobdoor', audience: 'jobdoor-api',
      });
      if (typeof decoded === 'string' || typeof decoded.sid !== 'string' || !Types.ObjectId.isValid(decoded.sid) ||
        typeof decoded.sub !== 'string' || !Types.ObjectId.isValid(decoded.sub)) throw invalidCredentials();
      payload = decoded;
    } catch { throw invalidCredentials(); }
    const session = await Session.findOne({
      _id: payload.sid, userId: payload.sub, revokedAt: null, expiresAt: { $gt: new Date() },
    });
    if (!session) throw invalidCredentials();
    const user = await User.findById(session.userId).select('+credentialVersion');
    if (!user || user.status !== AccountStatus.Active || !user.emailVerifiedAt || user.credentialVersion !== session.credentialVersion) {
      throw invalidCredentials();
    }
    return { user, session };
  }

  async logout(token: string): Promise<void> {
    const tokenHash = hashToken(token);
    const session = await Session.findOneAndUpdate({
      $or: [{ refreshHash: tokenHash }, { previousRefreshHashes: tokenHash }], revokedAt: null,
    }, { revokedAt: new Date() });
    if (session) await this.event(session.userId, AuthEventType.Logout);
  }

  async forgotPassword(email: string): Promise<void> {
    const token = randomBytes(32).toString('hex');
    const user = await User.findOneAndUpdate({
      email, status: AccountStatus.Active, passwordHash: { $exists: true },
      $or: [{ resetRequestedAt: null }, { resetRequestedAt: { $lte: new Date(Date.now() - RESEND_COOLDOWN_MS) } }],
    }, { $set: {
      resetTokenHash: hashToken(token), resetExpiresAt: new Date(Date.now() + RESET_LIFETIME_MS), resetRequestedAt: new Date(),
    } });
    if (!user) return;
    const url = new URL(this.settings.resetPasswordUrl);
    url.searchParams.set('token', token);
    try {
      await this.sendMail(email, 'Reset your Jobdoor password', `Reset your password (expires in 30 minutes): ${url}`);
    } catch (error) { reportError('password_reset_email_delivery_failed', error); }
  }

  async resetPassword(token: string, password: string): Promise<void> {
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.findOneAndUpdate({
      resetTokenHash: hashToken(token), resetExpiresAt: { $gt: new Date() }, status: AccountStatus.Active,
    }, {
      $set: { passwordHash }, $inc: { credentialVersion: 1 },
      $unset: { resetTokenHash: 1, resetExpiresAt: 1 },
    });
    if (!user) throw new HttpError(400, 'Invalid or expired password reset token');
    await Session.updateMany({ userId: user._id, revokedAt: null }, { revokedAt: new Date() });
    await this.event(user._id, AuthEventType.PasswordReset);
  }

  async onboard(userId: Types.ObjectId, userType: UserType, username?: string) {
    let user;
    try {
      user = await User.findOneAndUpdate({ _id: userId, onboardingCompletedAt: null }, { $set: {
        userType, role: userType === UserType.JobSeeker ? UserRole.Candidate : UserRole.User,
        onboardingCompletedAt: new Date(), ...(username ? { username } : {}),
      } }, { returnDocument: 'after', runValidators: true });
    } catch (error) {
      if (typeof error === 'object' && error && 'code' in error && error.code === 11000) {
        throw new HttpError(409, 'Username is unavailable');
      }
      throw error;
    }
    if (!user) throw new HttpError(409, 'Onboarding is already complete');
    await this.event(user._id, AuthEventType.OnboardingCompleted);
    return this.publicUser(user);
  }

  publicUser(user: { id: string; name: string; email: string; username?: string | null; role: string; userType?: string | null; emailVerifiedAt?: Date | null; onboardingCompletedAt?: Date | null }) {
    return {
      id: user.id, name: user.name, email: user.email, username: user.username ?? null,
      role: user.role, userType: user.userType ?? null, emailVerified: Boolean(user.emailVerifiedAt),
      onboardingComplete: Boolean(user.onboardingCompletedAt),
      nextStep: user.onboardingCompletedAt ? 'dashboard' : 'select_user_type',
    };
  }
}
