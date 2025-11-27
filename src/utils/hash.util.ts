// src/utils/hash.util.ts
import * as bcrypt from 'bcrypt';
import { config } from 'dotenv';
config();
const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '11', 10);

export async function hashString(plain: string): Promise<string> {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

export async function compareHash(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}
