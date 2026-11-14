import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js';
import { hashClientHash, generateServerSalt } from '../lib/auth.js';
import { badRequest, conflict, forbidden, notFound } from '../lib/errors.js';
import { Role } from '@prisma/client';

const createSchoolSchema = z.object({
  code: z.string().min(2).max(32).regex(/^[a-zA-Z0-9_-]+$/),
  name: z.string().min(2).max(120),
  deputyName: z.string().min(2).max(80),
  deputyUsername: z.string().min(3).max(40).regex(/^[a-zA-Z0-9._-]+$/),
  deputySalt: z.string().regex(/^[0-9a-f]{32}$/i),
  deputyHash: z.string().regex(/^[0-9a-f]{64}$/i),
});

const updateSchoolSchema = z.object({
  active: z.boolean().optional(),
  name: z.string().min(2).max(120).optional(),
});

export async function adminRoutes(app: FastifyInstance) {
  // All admin routes require superadmin
  app.addHook('preHandler', app.requireRole('superadmin'));

  /**
   * GET /api/admin/schools
   */
  app.get('/api/admin/schools', async () => {
    const schools = await prisma.school.findMany({
      orderBy: { createdAt: 'desc' },
      include: {
        _count: { select: { users: true, classes: true, students: true } },
        users: {
          where: { role: Role.deputy },
          select: { id: true, name: true, username: true, active: true },
          take: 5,
        },
      },
    });

    return {
      schools: schools.map((s) => ({
        id: s.id,
        code: s.code,
        name: s.name,
        active: s.active,
        settings: s.settings,
        createdAt: s.createdAt,
        counts: s._count,
        deputies: s.users,
      })),
    };
  });

  /**
   * POST /api/admin/schools
   * Creates school + first deputy in one transaction.
   */
  app.post('/api/admin/schools', async (req) => {
    const body = createSchoolSchema.safeParse(req.body);
    if (!body.success) {
      throw badRequest('داده‌های مدرسه نامعتبر است', 'VALIDATION');
    }

    const { code, name, deputyName, deputyUsername, deputySalt, deputyHash } = body.data;

    const existingCode = await prisma.school.findUnique({ where: { code } });
    if (existingCode) {
      throw conflict('کد مدرسه تکراری است');
    }

    // Store client salt; server hash = scrypt(clientHash, clientSalt)
    const serverHash = await hashClientHash(deputyHash, deputySalt);

    const result = await prisma.$transaction(async (tx) => {
      const school = await tx.school.create({
        data: {
          code,
          name,
          active: true,
          settings: {
            absenceThreshold: 3,
            lateThreshold: 5,
            academicYearStartMonth: 7, // Mehr
          },
        },
      });

      const deputy = await tx.user.create({
        data: {
          schoolId: school.id,
          username: deputyUsername,
          name: deputyName,
          role: Role.deputy,
          salt: deputySalt,
          hash: serverHash,
          active: true,
        },
      });

      await tx.auditLog.create({
        data: {
          schoolId: school.id,
          userId: req.user.uid,
          action: 'school.create',
          entity: 'school',
          entityId: school.id,
          details: { code, name, deputyUsername },
        },
      });

      return { school, deputy };
    });

    return {
      school: {
        id: result.school.id,
        code: result.school.code,
        name: result.school.name,
        active: result.school.active,
      },
      deputy: {
        id: result.deputy.id,
        name: result.deputy.name,
        username: result.deputy.username,
      },
    };
  });

  /**
   * PUT /api/admin/schools/:id
   */
  app.put('/api/admin/schools/:id', async (req) => {
    const { id } = req.params as { id: string };
    const body = updateSchoolSchema.safeParse(req.body);
    if (!body.success) {
      throw badRequest('داده نامعتبر است');
    }

    const school = await prisma.school.findUnique({ where: { id } });
    if (!school) throw notFound('مدرسه یافت نشد');

    const updated = await prisma.school.update({
      where: { id },
      data: {
        ...(body.data.active !== undefined && { active: body.data.active }),
        ...(body.data.name && { name: body.data.name }),
      },
    });

    await prisma.auditLog.create({
      data: {
        schoolId: id,
        userId: req.user.uid,
        action: 'school.update',
        entity: 'school',
        entityId: id,
        details: body.data,
      },
    });

    return {
      school: {
        id: updated.id,
        code: updated.code,
        name: updated.name,
        active: updated.active,
      },
    };
  });

  /**
   * DELETE /api/admin/schools/:id  (soft: deactivate + optional hard if no data)
   */
  app.delete('/api/admin/schools/:id', async (req) => {
    const { id } = req.params as { id: string };
    const school = await prisma.school.findUnique({ where: { id } });
    if (!school) throw notFound('مدرسه یافت نشد');

    const studentCount = await prisma.student.count({ where: { schoolId: id } });
    const classCount = await prisma.class.count({ where: { schoolId: id } });

    if (studentCount > 0 || classCount > 0) {
      // soft delete only
      await prisma.school.update({ where: { id }, data: { active: false } });
      await prisma.user.updateMany({ where: { schoolId: id }, data: { active: false } });
      await prisma.auditLog.create({
        data: {
          schoolId: id,
          userId: req.user.uid,
          action: 'school.deactivate',
          entity: 'school',
          entityId: id,
          details: { reason: 'delete_requested_with_data' },
        },
      });
      return { ok: true, soft: true };
    }

    await prisma.$transaction(async (tx) => {
      await tx.auditLog.deleteMany({ where: { schoolId: id } });
      await tx.attendance.deleteMany({ where: { schoolId: id } });
      await tx.user.deleteMany({ where: { schoolId: id } });
      await tx.school.delete({ where: { id } });
    });

    return { ok: true, soft: false };
  });
}

