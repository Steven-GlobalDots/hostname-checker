import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Bindings } from './types';
import { handleCheckHost } from './handlers/hostHandler';

const app = new Hono<{ Bindings: Bindings }>();

app.use('/api/*', cors());

app.post('/api/check-host', handleCheckHost);

app.get('/api/results', async (c) => {
  const results = await c.env.hosts_db.prepare('SELECT * FROM hosts ORDER BY updated_at DESC').all();
  return c.json(results.results);
});

export default app;
