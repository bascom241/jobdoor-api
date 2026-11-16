import { Schema, model } from 'mongoose';
import { AuthProvider } from './auth.enums.js';

const oauthStateSchema = new Schema({
  stateHash: { type: String, required: true, unique: true },
  provider: { type: String, enum: Object.values(AuthProvider), required: true },
  verifier: { type: String, required: true, select: false },
  expiresAt: { type: Date, required: true, expires: 0 },
});
export const OAuthState = model('OAuthState', oauthStateSchema);

const identitySchema = new Schema({
  provider: { type: String, enum: Object.values(AuthProvider), required: true },
  subject: { type: String, required: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
});
identitySchema.index({ provider: 1, subject: 1 }, { unique: true });
export const Identity = model('Identity', identitySchema);
