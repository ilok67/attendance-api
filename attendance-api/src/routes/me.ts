import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js';
import { verifyClientHash, hashClientHash, generateServerSalt } from '../lib/auth.js';
import { badRequest, unauthorized } from '../lib/errors.js';

export async function meRoutes(app: FastifyInstance) {
  /**
   * POST /api/me/password
   * Body: { currentHash, salt, hash }  — client hashes both old and new password
   * currentHash = PBKDF2(oldPassword), salt+hash = new client salt+hash of new password
   */
  app.post('/api/me/password', { preHandler: [app.authenticate] }, async (req) => {
    const schema = z.object({
      currentHash: z.string().regex(/^[0-9a-f]{64}$/i),
      salt: z.string().regex(/^[0-9a-f]{32}$/i),
      hash: z.string().regex(/^[0-9a-f]{64}$/i),
    });
    const body = schema.safeParse(req.body);
    if (!body.success) throw badRequest('داده نامعتبر است');

    const user = await prisma.user.findUnique({ where: { id: req.user.uid } });
    if (!user || !user.active) throw unauthorized();

    const valid = await verifyClientHash(body.data.currentHash, user.salt, user.hash);
    if (!valid) throw unauthorized('رمز فعلی نادرست است');

    // New client salt+hash from browser; store salt as-is
    const serverHash = await hashClientHash(body.data.hash, body.data.salt);

    await prisma.user.update({
      where: { id: user.id },
      data: { salt: body.data.salt, hash: serverHash },
    });

    return { ok: true };
  });
}
