import fp from 'fastify-plugin';
import fjwt from '@fastify/jwt';
import { FastifyReply, FastifyRequest } from 'fastify';
import { JwtPayload } from '../types/index.js';
import { unauthorized, forbidden } from '../lib/errors.js';

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: JwtPayload;
    user: JwtPayload;
  }
}

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireRole: (...roles: string[]) => (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

export default fp(async (app) => {
  await app.register(fjwt, {
    secret: process.env.JWT_SECRET || 'dev-secret-change-me',
    sign: { expiresIn: '12h' },
  });

  app.decorate('authenticate', async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      await req.jwtVerify();
    } catch {
      throw unauthorized();
    }
  });

  app.decorate('requireRole', (...roles: string[]) => {
    return async (req: FastifyRequest, _reply: FastifyReply) => {
      await app.authenticate(req, _reply);
      if (!roles.includes(req.user.role)) {
        throw forbidden('نقش شما اجازه این عملیات را ندارد');
      }
    };
  });
});
