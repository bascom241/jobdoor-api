import { Schema, model } from 'mongoose';
import { AccountStatus, UserRole, UserType } from './user.enums.js';

const userSchema = new Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, lowercase: true, trim: true, unique: true },
  passwordHash: { type: String, select: false },
  credentialVersion: { type: Number, default: 0, select: false },
  username: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  userType: { type: String, enum: Object.values(UserType), default: null },
  onboardingCompletedAt: { type: Date, default: null },
  role: { type: String, enum: Object.values(UserRole), default: UserRole.User, required: true },
  status: { type: String, enum: Object.values(AccountStatus), default: AccountStatus.PendingVerification, required: true },
  emailVerifiedAt: { type: Date, default: null },
  verificationTokenHash: { type: String, select: false },
  verificationExpiresAt: { type: Date, select: false },
  verificationAttempts: { type: Number, default: 0, select: false },
  verificationRequestedAt: { type: Date, default: Date.now, select: false },
  resetTokenHash: { type: String, select: false },
  resetExpiresAt: { type: Date, select: false },
  resetRequestedAt: { type: Date, select: false },
  verificationEmailSentAt: { type: Date, default: null },
}, { timestamps: true });

export const User = model('User', userSchema);
