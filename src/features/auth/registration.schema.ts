import { z } from 'zod';

export const registrationSchema = z.object({
  name: z.string().trim().min(2).max(100),
  email: z.email().trim().toLowerCase().max(254),
  // bcrypt only uses the first 72 bytes.
  password: z.string().min(8).refine(
    value => Buffer.byteLength(value, 'utf8') <= 72,
    'Password must be at most 72 UTF-8 bytes',
  ),
}).strict();

export type RegistrationInput = z.infer<typeof registrationSchema>;
