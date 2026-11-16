import { Schema, model } from 'mongoose';

const sessionSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  refreshHash: { type: String, required: true, unique: true, select: false },
  previousRefreshHashes: { type: [String], default: [], select: false },
  persistent: { type: Boolean, required: true },
  credentialVersion: { type: Number, required: true },
  expiresAt: { type: Date, required: true, expires: 0 },
  revokedAt: { type: Date, default: null },
}, { timestamps: true });

export const Session = model('Session', sessionSchema);
