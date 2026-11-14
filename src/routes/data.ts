import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js';
import { badRequest, forbidden, unauthorized } from '../lib/errors.js';
import { AttendanceStatus, Role, Shift } from '@prisma/client';
import { verifyClientHash } from '../lib/auth.js';

export async function dataRoutes(app: FastifyInstance) {
  /**
   * GET /api/data
   * Returns all data the current user is allowed to see.
   * Teacher → only their classes + students + attendance
   * Deputy → entire school
   * Superadmin → should use admin endpoints
   */
  app.get('/api/data', { preHandler: [app.authenticate] }, async (req) => {
    const { uid, sid: tokenSchoolId, role } = req.user;

    // Superadmin may act on a school via ?schoolId=
    let sid: string | null | undefined = tokenSchoolId;
    if (role === Role.superadmin) {
      const q = (req.query as { schoolId?: string }).schoolId;
      if (!q) throw forbidden('برای سوپرادمین پارامتر schoolId الزامی است');
      sid = q;
    }

    if (!sid) {
      throw forbidden('مدرسه مشخص نیست');
    }

    const school = await prisma.school.findUnique({
      where: { id: sid },
      select: { id: true, code: true, name: true, active: true, settings: true },
    });

    if (!school) {
      throw forbidden('مدرسه یافت نشد');
    }
    if (!school.active && role !== Role.superadmin) {
      throw forbidden('مدرسه غیرفعال است');
    }

    const classWhere =
      role === Role.teacher
        ? { schoolId: sid, teacherId: uid, active: true }
        : { schoolId: sid, active: true };

    const classes = await prisma.class.findMany({
      where: classWhere,
      orderBy: [{ grade: 'asc' }, { name: 'asc' }],
      include: {
        teacher: { select: { id: true, name: true, username: true } },
      },
    });

    const classIds = classes.map((c) => c.id);

    const students = await prisma.student.findMany({
      where: { schoolId: sid, classId: { in: classIds }, active: true },
      orderBy: { fullName: 'asc' },
    });

    // Last 90 days of attendance for these classes
    const since = new Date();
    since.setDate(since.getDate() - 90);

    const attendance = await prisma.attendance.findMany({
      where: {
        schoolId: sid,
        classId: { in: classIds },
        date: { gte: since },
      },
      orderBy: { date: 'desc' },
    });

    const users =
      role === Role.deputy || role === Role.superadmin
        ? await prisma.user.findMany({
            where: { schoolId: sid },
            select: {
              id: true,
              name: true,
              username: true,
              role: true,
              active: true,
            },
          })
        : [];

    return {
      school: {
        id: school.id,
        code: school.code,
        name: school.name,
        settings: school.settings,
      },
      classes: classes.map((c) => ({
        id: c.id,
        name: c.name,
        grade: c.grade,
        shift: c.shift,
        teacherId: c.teacherId,
        teacherName: c.teacher?.name ?? null,
        academicYear: c.academicYear,
      })),
      students: students.map((s) => ({
        id: s.id,
        classId: s.classId,
        fullName: s.fullName,
        studentCode: s.studentCode,
      })),
      attendance: attendance.map((a) => ({
        id: a.id,
        studentId: a.studentId,
        classId: a.classId,
        date: a.date.toISOString().slice(0, 10),
        shift: a.shift,
        status: a.status,
        note: a.note,
        updatedAt: a.updatedAt.toISOString(),
        history: a.history,
      })),
      users,
    };
  });

  /**
   * POST /api/sync
   * Authenticated by credentials (not just JWT) so offline queue can sync.
   */
  app.post('/api/sync', async (req) => {
    const schema = z.object({
      schoolCode: z.string().min(1),
      username: z.string().min(1),
      salt: z.string().regex(/^[0-9a-f]{32}$/i),
      hash: z.string().regex(/^[0-9a-f]{64}$/i),
      records: z.array(
        z.object({
          classId: z.string().min(1),
          studentId: z.string().min(1),
          date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
          shift: z.nativeEnum(Shift),
          status: z.nativeEnum(AttendanceStatus),
          note: z.string().max(500).optional(),
          updatedAt: z.string().datetime(),
        })
      ),
    });

    const body = schema.safeParse(req.body);
    if (!body.success) {
      throw badRequest('داده سینک نامعتبر است');
    }

    const { schoolCode, username, hash: clientHash, records } = body.data;

    const school = await prisma.school.findUnique({ where: { code: schoolCode } });
    if (!school || !school.active) {
      throw unauthorized('کد مدرسه یا اطلاعات ورود نادرست است');
    }

    const user = await prisma.user.findUnique({
      where: { schoolId_username: { schoolId: school.id, username } },
    });

    if (!user || !user.active) {
      throw unauthorized('نام کاربری یا رمز عبور نادرست است');
    }

    const valid = await verifyClientHash(clientHash, user.salt, user.hash);
    if (!valid) {
      throw unauthorized('همگام‌سازی ممکن نیست: نام کاربری یا رمز عبور با سرور مطابقت ندارد');
    }

    const saved: string[] = [];
    const rejected: { key: string; reason: string }[] = [];

    for (const rec of records) {
      const key = `${rec.studentId}|${rec.date}|${rec.shift}`;

      try {
        // Validate class belongs to school
        const cls = await prisma.class.findFirst({
          where: { id: rec.classId, schoolId: school.id, active: true },
        });
        if (!cls) {
          rejected.push({ key, reason: 'کلاس نامعتبر' });
          continue;
        }

        // Teacher can only write their own classes
        if (user.role === Role.teacher && cls.teacherId !== user.id) {
          rejected.push({ key, reason: 'دسترسی به این کلاس ندارید' });
          continue;
        }

        const student = await prisma.student.findFirst({
          where: {
            id: rec.studentId,
            schoolId: school.id,
            classId: rec.classId,
            active: true,
          },
        });
        if (!student) {
          rejected.push({ key, reason: 'دانش‌آموز نامعتبر' });
          continue;
        }

        const dateObj = new Date(rec.date + 'T00:00:00.000Z');

        const existing = await prisma.attendance.findUnique({
          where: {
            schoolId_studentId_date_shift: {
              schoolId: school.id,
              studentId: rec.studentId,
              date: dateObj,
              shift: rec.shift,
            },
          },
        });

        const historyEntry = {
          status: rec.status,
          note: rec.note ?? null,
          by: user.id,
          at: new Date().toISOString(),
        };

        if (existing) {
          // Only update if incoming is newer
          if (new Date(rec.updatedAt) < existing.updatedAt) {
            rejected.push({ key, reason: 'نسخه قدیمی‌تر از سرور' });
            continue;
          }

          const history = Array.isArray(existing.history) ? existing.history : [];
          history.push(historyEntry);

          await prisma.attendance.update({
            where: { id: existing.id },
            data: {
              status: rec.status,
              note: rec.note ?? null,
              recordedBy: user.id,
              history,
              updatedAt: new Date(),
            },
          });
        } else {
          await prisma.attendance.create({
            data: {
              schoolId: school.id,
              studentId: rec.studentId,
              classId: rec.classId,
              date: dateObj,
              shift: rec.shift,
              status: rec.status,
              note: rec.note ?? null,
              recordedBy: user.id,
              history: [historyEntry],
            },
          });
        }

        saved.push(key);
      } catch (err) {
        rejected.push({ key, reason: 'خطای ذخیره‌سازی' });
      }
    }

    return { ok: true, saved: saved.length, rejected };
  });
}
