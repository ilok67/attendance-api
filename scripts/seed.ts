/**
 * Seed superadmin.
 * Usage: npx tsx scripts/seed.ts
 */
import 'dotenv/config';
import { prisma } from '../src/lib/prisma.js';
import { hashClientHash } from '../src/lib/auth.js';
import { Role } from '@prisma/client';
import { pbkdf2Sync, randomBytes } from 'node:crypto';

async function main() {
  const username = 'superadmin';
  const password = 'SuperAdmin@1403';

  // Same algorithm as browser client
  const clientSalt = randomBytes(16).toString('hex');
  const clientHash = pbkdf2Sync(password, Buffer.from(clientSalt, 'hex'), 100000, 32, 'sha256').toString('hex');

  // Store client salt; server hash = scrypt(clientHash, clientSalt)
  const serverHash = await hashClientHash(clientHash, clientSalt);

  const existing = await prisma.user.findFirst({
    where: { role: Role.superadmin, username },
  });

  if (existing) {
    // Reset password so login works after auth fix
    await prisma.user.update({
      where: { id: existing.id },
      data: { salt: clientSalt, hash: serverHash, active: true },
    });
    console.log('Superadmin password reset.');
    console.log('  username:', username);
    console.log('  password:', password);
    return;
  }

  const user = await prisma.user.create({
    data: {
      username,
      name: 'مدیر کل سامانه',
      role: Role.superadmin,
      schoolId: null,
      salt: clientSalt,
      hash: serverHash,
      active: true,
    },
  });

  console.log('Superadmin created successfully');
  console.log('  username:', username);
  console.log('  password:', password);
  console.log('  user id:', user.id);
  console.log('');
  console.log('IMPORTANT: Change the password after first login.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
