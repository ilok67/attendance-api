import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js';
import { hashClientHash, verifyClientHash, generateServerSalt, fakeSalt } from '../lib/auth.js';
import { unauthorized, badRequest } from '../lib/errors.js';
import { Role } from '@prisma/client';

const loginSchema = z.object({
  schoolCode: z.string().min(1),
  username: z.string().min(1),
  salt: z.string().regex(/^[0-9a-f]{32}$/i), // 16 bytes hex
  hash: z.string().regex(/^[0-9a-f]{64}$/i), // 32 bytes hex
});

export async function authRoutes(app: FastifyInstance) {
  /**
   * GET /api/salt?schoolCode=xxx&username=yyy
   * Returns the server salt for an existing user, or a deterministic fake salt
   * so that attackers cannot enumerate valid usernames.
   */
  app.get('/api/salt', async (req) => {
    const q = z
      .object({
        schoolCode: z.string().min(1),
        username: z.string().min(1),
      })
      .safeParse(req.query);

    if (!q.success) {
      throw badRequest('پارامترهای schoolCode و username الزامی است');
    }

    const { schoolCode, username } = q.data;

    // Superadmin has no school
    if (schoolCode === 'ADMIN' || schoolCode === 'admin') {
      const user = await prisma.user.findFirst({
        where: { username, role: Role.superadmin, schoolId: null },
      });
      if (user) return { salt: user.salt };
      return { salt: fakeSalt(username, 'ADMIN') };
    }

    const school = await prisma.school.findUnique({ where: { code: schoolCode } });
    if (!school || !school.active) {
      return { salt: fakeSalt(username, schoolCode) };
    }

    const user = await prisma.user.findUnique({
      where: { schoolId_username: { schoolId: school.id, username } },
    });

    if (!user || !user.active) {
      return { salt: fakeSalt(username, schoolCode) };
    }

    return { salt: user.salt };
  });

  /**
   * POST /api/login
   * Body: { schoolCode, username, salt (client), hash (client PBKDF2) }
   */
  app.post('/api/login', async (req) => {
    const body = loginSchema.safeParse(req.body);
    if (!body.success) {
      throw badRequest('داده‌های ورود نامعتبر است');
    }

    const { schoolCode, username, salt: clientSalt, hash: clientHash } = body.data;

    let user;
    let school = null;

    if (schoolCode === 'ADMIN' || schoolCode === 'admin') {
      user = await prisma.user.findFirst({
        where: { username, role: Role.superadmin, schoolId: null, active: true },
      });
    } else {
      school = await prisma.school.findUnique({ where: { code: schoolCode } });
      if (!school || !school.active) {
        throw unauthorized('کد مدرسه یا اطلاعات ورود نادرست است');
      }

      user = await prisma.user.findUnique({
        where: { schoolId_username: { schoolId: school.id, username } },
      });
    }

    if (!user || !user.active) {
      throw unauthorized('نام کاربری یا رمز عبور نادرست است');
    }

    const valid = await verifyClientHash(clientHash, user.salt, user.hash);
    if (!valid) {
      throw unauthorized('نام کاربری یا رمز عبور نادرست است');
    }

    const token = app.jwt.sign({
      uid: user.id,
      sid: user.schoolId,
      role: user.role,
    });

    return {
      token,
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        role: user.role,
      },
      school: school
        ? {
            id: school.id,
            code: school.code,
            name: school.name,
            settings: school.settings,
          }
        : null,
    };
  });
}
