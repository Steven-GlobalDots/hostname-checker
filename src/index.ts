import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Bindings, Job } from './types';
export { HostCheckWorkflow } from './workflow';

const app = new Hono<{ Bindings: Bindings }>();

// Version: 2026-02-03-15:06 - Verified push to Steven-GlobalDots

app.use('/api/*', cors());

app.post('/api/check-host', async (c) => {
  const { hostname } = await c.req.json<{ hostname: string }>();
  if (!hostname) return c.json({ error: 'Hostname required' }, 400);

  const jobId = crypto.randomUUID();
  const now = Date.now();

  // 1. Create Job Record
  await c.env.hosts_db.prepare(
    `INSERT INTO jobs (id, hostname, status, created_at, updated_at) VALUES (?, ?, 'pending', ?, ?)`
  ).bind(jobId, hostname, now, now).run();

  // 2. Trigger Workflow
  await c.env.HOST_CHECK_WORKFLOW.create({
    id: jobId, // Use jobId as workflow ID for easier tracking/deduplication if needed
    params: {
      hostname,
      jobId
    }
  });

  return c.json({ success: true, jobId });
});

app.get('/api/jobs/:id', async (c) => {
  const jobId = c.req.param('id');
  const job = await c.env.hosts_db.prepare('SELECT * FROM jobs WHERE id = ?').bind(jobId).first<Job>();

  if (!job) {
    return c.json({ error: 'Job not found' }, 404);
  }

  return c.json(job);
});

app.delete('/api/results', async (c) => {
  try {
    await c.env.hosts_db.prepare('DELETE FROM hosts').run();
    // Optional: also clear jobs? 
    // await c.env.hosts_db.prepare('DELETE FROM jobs').run(); 
    return c.json({ success: true, message: 'All records cleared' });
  } catch (e: any) {
    return c.json({ success: false, error: e.message }, 500);
  }
});

app.get('/api/results', async (c) => {
  const results = await c.env.hosts_db.prepare('SELECT * FROM hosts ORDER BY updated_at DESC').all();
  return c.json(results.results);
});

export default app;
