import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { register, type RegistrationDependencies } from './registration.service.js';
import { registrationSchema } from './registration.schema.js';

export function createAuthRouter(deps: RegistrationDependencies) {
  const router = Router();
  router.post('/register', rateLimit({
    windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false,
  }), async (req, res) => {
    const result = registrationSchema.safeParse(req.body);
    if (!result.success) {
      res.status(400).json({ message: 'Invalid registration input', errors: result.error.flatten().fieldErrors });
      return;
    }
    await register(result.data, deps);
    res.status(202).json({ message: 'If registration is available for this email, verification instructions will be sent.' });
  });
  return router;
}
