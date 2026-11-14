import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import authPlugin from './plugins/auth.js';
import { authRoutes } from './routes/auth.js';
import { adminRoutes } from './routes/admin.js';
import { dataRoutes } from './routes/data.js';
import { deputyRoutes } from './routes/deputy.js';
import { meRoutes } from './routes/me.js';
import { AppError } from './lib/errors.js';

const app = Fastify({
  logger: {
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  },
});

app.setErrorHandler((error, _request, reply) => {
  if (error instanceof AppError) {
    return reply.status(error.statusCode).send({
      error: error.message,
      code: error.code,
    });
  }

  const err = error as Error & { validation?: unknown };
  if (err.validation) {
    return reply.status(400).send({
      error: 'داده ورودی نامعتبر است',
      details: err.validation,
    });
  }

  app.log.error(error);
  return reply.status(500).send({ error: 'خطای داخلی سرور' });
});

async function main() {
  await app.register(cors, {
    origin: [
      'http://localhost:5173',
      'https://attendance-web.iloktest6.workers.dev',
      'http://localhost:4173',
      'capacitor://localhost',
      'http://localhost',
      'https://tauri.localhost',
      'tauri://localhost',
      // Cloudflare Pages / production frontends — add your real domain:
      /\.pages\.dev$/,
      /\.onrender\.com$/,
      /\.vercel\.app$/,
    ],
    credentials: true,
  });

  await app.register(rateLimit, {
    max: 200,
    timeWindow: '1 minute',
  });

  await app.register(authPlugin);
  await app.register(authRoutes);
  await app.register(adminRoutes);
  await app.register(dataRoutes);
  await app.register(deputyRoutes);
  await app.register(meRoutes);

  app.get('/api/health', async () => ({
    ok: true,
    time: new Date().toISOString(),
  }));

  const port = Number(process.env.PORT) || 3000;
  await app.listen({ port, host: '0.0.0.0' });
  console.log(`API running on http://localhost:${port}`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
