// src/utils/token.util.ts
import { randomBytes } from 'crypto';
import { sign } from 'jsonwebtoken';
import { config } from 'dotenv';
config();

export function generateRandomTokenHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

export function signAccessToken(payload: any) {
  const secret = process.env.JWT_ACCESS_SECRET!;
  const expiresIn = process.env.JWT_ACCESS_EXPIRATION || '900s';
  return sign(payload, secret, { expiresIn });
}

export function signRefreshToken(payload: any) {
  const secret = process.env.JWT_REFRESH_SECRET!;
  const expiresIn = process.env.JWT_REFRESH_EXPIRATION || '7d';
  return sign(payload, secret, { expiresIn });
}
