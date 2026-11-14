import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js';
import { hashClientHash, generateServerSalt } from '../lib/auth.js';
import { badRequest, conflict, forbidden, notFound } from '../lib/errors.js';
import { Role, Shift } from '@prisma/client';

function requireSchool(req: any): string {
  // Superadmin can target a school via header x-school-id
  if (req.user.role === 'superadmin') {
    const hid = req.headers['x-school-id'];
    if (typeof hid === 'string' && hid.length > 0) return hid;
    throw forbidden('هدر x-school-id برای سوپرادمین الزامی است');
  }
  if (!req.user.sid) throw forbidden('مدرسه مشخص نیست');
  return req.user.sid;
}

export async function deputyRoutes(app: FastifyInstance) {
  app.addHook('preHandler', app.requireRole('deputy', 'superadmin'));

  // ─── Classes ───────────────────────────────────────────────

  app.post('/api/classes', async (req) => {
    const schoolId = requireSchool(req);
    const schema = z.object({
      name: z.string().min(1).max(60),
      grade: z.number().int().min(1).max(6),
      shift: z.nativeEnum(Shift),
      teacherId: z.string().optional().nullable(),
      academicYear: z.string().regex(/^\d{4}-\d{4}$/),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('داده کلاس نامعتبر است');

    const cls = await prisma.class.create({
      data: {
        schoolId,
        name: body.data.name,
        grade: body.data.grade,
        shift: body.data.shift,
        teacherId: body.data.teacherId ?? null,
        academicYear: body.data.academicYear,
      },
    });

    return { class: cls };
  });

  app.put('/api/classes/:id', async (req) => {
    const schoolId = requireSchool(req);
    const { id } = req.params as { id: string };
    const schema = z.object({
      name: z.string().min(1).max(60).optional(),
      grade: z.number().int().min(1).max(6).optional(),
      shift: z.nativeEnum(Shift).optional(),
      teacherId: z.string().nullable().optional(),
      active: z.boolean().optional(),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('داده نامعتبر است');

    const existing = await prisma.class.findFirst({ where: { id, schoolId } });
    if (!existing) throw notFound('کلاس یافت نشد');

    const updated = await prisma.class.update({
      where: { id },
      data: body.data,
    });
    return { class: updated };
  });

  app.delete('/api/classes/:id', async (req) => {
    const schoolId = requireSchool(req);
    const { id } = req.params as { id: string };

    const existing = await prisma.class.findFirst({ where: { id, schoolId } });
    if (!existing) throw notFound('کلاس یافت نشد');

    const studentCount = await prisma.student.count({
      where: { classId: id, active: true },
    });
    if (studentCount > 0) {
      throw conflict('کلاس دارای دانش‌آموز فعال است و قابل حذف نیست');
    }

    await prisma.class.update({ where: { id }, data: { active: false } });
    return { ok: true };
  });

  // ─── Students ──────────────────────────────────────────────

  app.post('/api/students', async (req) => {
    const schoolId = requireSchool(req);
    const schema = z.object({
      classId: z.string().min(1),
      fullName: z.string().min(2).max(80),
      studentCode: z.string().min(1).max(32),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('داده دانش‌آموز نامعتبر است');

    const cls = await prisma.class.findFirst({
      where: { id: body.data.classId, schoolId, active: true },
    });
    if (!cls) throw badRequest('کلاس نامعتبر است');

    try {
      const student = await prisma.student.create({
        data: {
          schoolId,
          classId: body.data.classId,
          fullName: body.data.fullName,
          studentCode: body.data.studentCode,
        },
      });
      return { student };
    } catch (e: any) {
      if (e.code === 'P2002') throw conflict('کد دانش‌آموز تکراری است');
      throw e;
    }
  });

  app.post('/api/students/import', async (req) => {
    const schoolId = requireSchool(req);
    const schema = z.object({
      classId: z.string().min(1),
      rows: z.array(
        z.object({
          fullName: z.string().min(2).max(80),
          code: z.string().min(1).max(32),
        })
      ),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('داده ایمپورت نامعتبر است');

    const cls = await prisma.class.findFirst({
      where: { id: body.data.classId, schoolId, active: true },
    });
    if (!cls) throw badRequest('کلاس نامعتبر است');

    let added = 0;
    const rejected: { code: string; reason: string }[] = [];

    for (const row of body.data.rows) {
      try {
        await prisma.student.create({
          data: {
            schoolId,
            classId: body.data.classId,
            fullName: row.fullName,
            studentCode: row.code,
          },
        });
        added++;
      } catch (e: any) {
        if (e.code === 'P2002') {
          rejected.push({ code: row.code, reason: 'کد تکراری' });
        } else {
          rejected.push({ code: row.code, reason: 'خطا' });
        }
      }
    }

    return { added, rejected };
  });

  app.put('/api/students/:id', async (req) => {
    const schoolId = requireSchool(req);
    const { id } = req.params as { id: string };
    const schema = z.object({
      fullName: z.string().min(2).max(80).optional(),
      studentCode: z.string().min(1).max(32).optional(),
      classId: z.string().optional(),
      active: z.boolean().optional(),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('داده نامعتبر است');

    const existing = await prisma.student.findFirst({ where: { id, schoolId } });
    if (!existing) throw notFound('دانش‌آموز یافت نشد');

    if (body.data.classId) {
      const cls = await prisma.class.findFirst({
        where: { id: body.data.classId, schoolId, active: true },
      });
      if (!cls) throw badRequest('کلاس نامعتبر است');
    }

    try {
      const updated = await prisma.student.update({
        where: { id },
        data: body.data,
      });
      return { student: updated };
    } catch (e: any) {
      if (e.code === 'P2002') throw conflict('کد دانش‌آموز تکراری است');
      throw e;
    }
  });

  app.delete('/api/students/:id', async (req) => {
    const schoolId = requireSchool(req);
    const { id } = req.params as { id: string };

    const existing = await prisma.student.findFirst({ where: { id, schoolId } });
    if (!existing) throw notFound('دانش‌آموز یافت نشد');

    await prisma.student.update({ where: { id }, data: { active: false } });
    return { ok: true };
  });

  // ─── Users (teachers) ──────────────────────────────────────

  app.post('/api/users', async (req) => {
    const schoolId = requireSchool(req);
    const schema = z.object({
      name: z.string().min(2).max(80),
      username: z.string().min(3).max(40).regex(/^[a-zA-Z0-9._-]+$/),
      role: z.enum(['teacher', 'deputy']),
      salt: z.string().regex(/^[0-9a-f]{32}$/i),
      hash: z.string().regex(/^[0-9a-f]{64}$/i),
      classIds: z.array(z.string()).optional(),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('داده کاربر نامعتبر است');

    if (body.data.role === 'deputy' && req.user.role !== 'deputy') {
      // only existing deputy can create another? or restrict
    }

    // Store client-provided salt
    const serverHash = await hashClientHash(body.data.hash, body.data.salt);

    try {
      const user = await prisma.$transaction(async (tx) => {
        const u = await tx.user.create({
          data: {
            schoolId,
            name: body.data.name,
            username: body.data.username,
            role: body.data.role as Role,
            salt: body.data.salt,
            hash: serverHash,
          },
        });

        if (body.data.classIds?.length) {
          await tx.class.updateMany({
            where: { id: { in: body.data.classIds }, schoolId },
            data: { teacherId: u.id },
          });
        }

        return u;
      });

      return {
        user: {
          id: user.id,
          name: user.name,
          username: user.username,
          role: user.role,
        },
      };
    } catch (e: any) {
      if (e.code === 'P2002') throw conflict('نام کاربری تکراری است');
      throw e;
    }
  });

  app.put('/api/users/:id', async (req) => {
    const schoolId = requireSchool(req);
    const { id } = req.params as { id: string };
    const schema = z.object({
      name: z.string().min(2).max(80).optional(),
      active: z.boolean().optional(),
      salt: z.string().regex(/^[0-9a-f]{32}$/i).optional(),
      hash: z.string().regex(/^[0-9a-f]{64}$/i).optional(),
      classIds: z.array(z.string()).optional(),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('داده نامعتبر است');

    const existing = await prisma.user.findFirst({ where: { id, schoolId } });
    if (!existing) throw notFound('کاربر یافت نشد');

    // Prevent self-deactivation / self-demotion
    if (id === req.user.uid && body.data.active === false) {
      throw forbidden('نمی‌توانید حساب خود را غیرفعال کنید');
    }

    const data: any = {};
    if (body.data.name) data.name = body.data.name;
    if (body.data.active !== undefined) data.active = body.data.active;

    if (body.data.salt && body.data.hash) {
      data.salt = body.data.salt;
      data.hash = await hashClientHash(body.data.hash, body.data.salt);
    }

    const updated = await prisma.$transaction(async (tx) => {
      const u = await tx.user.update({ where: { id }, data });

      if (body.data.classIds) {
        // Clear previous assignments
        await tx.class.updateMany({
          where: { teacherId: id, schoolId },
          data: { teacherId: null },
        });
        if (body.data.classIds.length) {
          await tx.class.updateMany({
            where: { id: { in: body.data.classIds }, schoolId },
            data: { teacherId: id },
          });
        }
      }

      return u;
    });

    return {
      user: {
        id: updated.id,
        name: updated.name,
        username: updated.username,
        role: updated.role,
        active: updated.active,
      },
    };
  });

  // ─── School settings ───────────────────────────────────────

  app.put('/api/school/settings', async (req) => {
    const schoolId = requireSchool(req);
    const schema = z.object({
      absenceThreshold: z.number().int().min(1).max(30).optional(),
      lateThreshold: z.number().int().min(1).max(30).optional(),
      academicYearStartMonth: z.number().int().min(1).max(12).optional(),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('تنظیمات نامعتبر است');

    const school = await prisma.school.findUnique({ where: { id: schoolId } });
    if (!school) throw notFound();

    const settings = { ...(school.settings as object), ...body.data };

    const updated = await prisma.school.update({
      where: { id: schoolId },
      data: { settings },
    });

    return { settings: updated.settings };
  });

  // ─── Audit log ─────────────────────────────────────────────

  app.get('/api/audit', async (req) => {
    const schoolId = requireSchool(req);
    const logs = await prisma.auditLog.findMany({
      where: { schoolId },
      orderBy: { createdAt: 'desc' },
      take: 100,
      include: {
        user: { select: { name: true, username: true } },
      },
    });
    return { logs };
  });
}
