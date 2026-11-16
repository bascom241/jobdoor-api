import { Schema, model } from 'mongoose';
import { AuthEventType } from './auth.enums.js';

const authEventSchema = new Schema({
  type: { type: String, enum: Object.values(AuthEventType), required: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
}, { timestamps: true });

export const AuthEvent = model('AuthEvent', authEventSchema);
