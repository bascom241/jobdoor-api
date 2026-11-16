import { z } from 'zod';
import { registrationSchema } from './registration.schema.js';
import { UserType } from '../users/user.enums.js';

export const emailSchema = z.object({ email: z.email().trim().toLowerCase().max(254) }).strict();
export const verifyEmailSchema = emailSchema.extend({ code: z.string().regex(/^\d{6}$/) });
export const loginSchema = z.object({
  identifier: z.string().trim().toLowerCase().min(1).max(254),
  password: z.string().min(1).max(256),
  keepMeSignedIn: z.boolean().default(false),
}).strict();
export const resetPasswordSchema = z.object({
  token: z.string().regex(/^[a-f0-9]{64}$/),
  password: registrationSchema.shape.password,
}).strict();
export const onboardingSchema = z.object({
  userType: z.enum(UserType),
  username: z.string().trim().toLowerCase().regex(/^[a-z0-9_]{3,30}$/).optional(),
}).strict();
