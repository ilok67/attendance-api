import { scrypt, randomBytes, timingSafeEqual, createHmac } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: string,
  keylen: number,
  options?: { N?: number; r?: number; p?: number }
) => Promise<Buffer>;

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEYLEN = 64;

/**
 * Server-side: hash the client-provided PBKDF2 hash with a server salt.
 * clientHash = PBKDF2-SHA256(password, clientSalt, 100000, 32) as hex
 */
export async function hashClientHash(clientHash: string, serverSalt: string): Promise<string> {
  const derived = await scryptAsync(clientHash, serverSalt, KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return derived.toString('hex');
}

export async function verifyClientHash(
  clientHash: string,
  serverSalt: string,
  storedHash: string
): Promise<boolean> {
  const derived = await scryptAsync(clientHash, serverSalt, KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  const stored = Buffer.from(storedHash, 'hex');
  if (derived.length !== stored.length) return false;
  return timingSafeEqual(derived, stored);
}

export function generateServerSalt(): string {
  return randomBytes(16).toString('hex');
}

/** Fake salt for non-existent users (prevents user enumeration) */
export function fakeSalt(username: string, schoolCode: string): string {
  return createHmac('sha256', process.env.JWT_SECRET || 'fallback')
    .update(`fake-salt:${schoolCode}:${username}`)
    .digest('hex')
    .slice(0, 32);
}
