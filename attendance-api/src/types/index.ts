import { Role, Shift, AttendanceStatus } from '@prisma/client';

export type { Role, Shift, AttendanceStatus };

export interface JwtPayload {
  uid: string;
  sid: string | null; // schoolId, null for superadmin
  role: Role;
}

export interface LoginBody {
  schoolCode: string;
  username: string;
  salt: string;   // client salt (hex)
  hash: string;   // client PBKDF2 hash (hex)
}

export interface SyncRecord {
  classId: string;
  studentId: string;
  date: string; // YYYY-MM-DD
  shift: Shift;
  status: AttendanceStatus;
  note?: string;
  updatedAt: string; // ISO
}
