process.env.NODE_ENV = 'test';
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { createApp } = require('../src/app');
const { createDb } = require('../src/db');

let server, base;
before(async () => {
  server = createApp(createDb(':memory:')).listen(0);
  base = `http://localhost:${server.address().port}`;
});
after(() => server.close());

const call = async (method, url, body, token) => {
  const r = await fetch(base + url, {
    method, headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, body: r.status === 204 ? null : await r.json() };
};
const login = async (email, password) => (await call('POST', '/api/auth/login', { email, password })).body.token;

test('register, duplicate email, weak password, login, bad login', async () => {
  const ok = await call('POST', '/api/auth/register', { name: 'Ravi', email: 'ravi@x.com', password: 'password1' });
  assert.equal(ok.status, 201);
  assert.ok(ok.body.token);
  assert.equal((await call('POST', '/api/auth/register', { name: 'R', email: 'ravi@x.com', password: 'password1' })).status, 409);
  assert.equal((await call('POST', '/api/auth/register', { name: 'R', email: 'a@b.com', password: 'short' })).status, 400);
  assert.equal((await call('POST', '/api/auth/login', { email: 'ravi@x.com', password: 'wrong' })).status, 401);
  assert.equal((await call('POST', '/api/auth/login', { email: 'ravi@x.com', password: 'password1' })).status, 200);
});

test('protected routes require a valid token', async () => {
  assert.equal((await call('GET', '/api/tickets')).status, 401);
  assert.equal((await call('GET', '/api/tickets', null, 'garbage')).status, 401);
});

test('RBAC: normal user cannot see devices or audit log', async () => {
  const t = await login('ravi@x.com', 'password1');
  assert.equal((await call('GET', '/api/devices', null, t)).status, 403);
  assert.equal((await call('GET', '/api/audit', null, t)).status, 403);
});

test('ticket lifecycle with ownership isolation, search, filters, pagination', async () => {
  const user = await login('ravi@x.com', 'password1');
  const agent = await login('agent@endpointops.dev', 'Agent@123');
  const admin = await login('admin@endpointops.dev', 'Admin@123');

  assert.equal((await call('POST', '/api/tickets', { title: '' }, user)).status, 400);
  const t1 = await call('POST', '/api/tickets', { title: 'VPN not connecting', description: 'Timeout on login', priority: 'high', device_id: 1 }, user);
  assert.equal(t1.status, 201);
  assert.equal(t1.body.device_hostname, 'blr-lap-001');
  await call('POST', '/api/tickets', { title: 'Printer offline', description: 'Floor 2' }, agent);

  // isolation: user sees only own tickets, agent sees all
  assert.equal((await call('GET', '/api/tickets', null, user)).body.total, 1);
  assert.equal((await call('GET', '/api/tickets', null, agent)).body.total, 2);

  // search + filter
  assert.equal((await call('GET', '/api/tickets?q=vpn', null, agent)).body.total, 1);
  assert.equal((await call('GET', '/api/tickets?priority=high', null, agent)).body.total, 1);
  assert.equal((await call('GET', '/api/tickets?limit=1&page=2', null, agent)).body.items.length, 1);

  // SQL injection attempt in search is harmless (parameterised)
  assert.equal((await call('GET', "/api/tickets?q=' OR 1=1 --", null, agent)).body.total, 0);
  assert.equal((await call('GET', '/api/tickets?sort=id;DROP TABLE tickets', null, agent)).status, 200);

  // users cannot change status; agents can
  assert.equal((await call('PATCH', `/api/tickets/${t1.body.id}`, { status: 'closed' }, user)).status, 403);
  const agentUser = (await call('GET', '/api/auth/me', null, agent)).body.user;
  const upd = await call('PATCH', `/api/tickets/${t1.body.id}`, { status: 'in_progress', assignee_id: agentUser.id }, agent);
  assert.equal(upd.body.status, 'in_progress');
  assert.equal(upd.body.assignee_name, 'Asha Agent');

  // comments, and another user cannot read someone else's ticket
  assert.equal((await call('POST', `/api/tickets/${t1.body.id}/comments`, { body: 'Reset your token' }, agent)).status, 201);
  assert.equal((await call('GET', `/api/tickets/${t1.body.id}`, null, user)).body.comments.length, 1);
  const other = (await call('POST', '/api/auth/register', { name: 'Eve', email: 'eve@x.com', password: 'password1' })).body.token;
  assert.equal((await call('GET', `/api/tickets/${t1.body.id}`, null, other)).status, 404);

  // stats and audit
  assert.equal((await call('GET', '/api/stats', null, agent)).body.ticketsByStatus.in_progress, 1);
  assert.ok((await call('GET', '/api/audit', null, admin)).body.length > 0);

  // only admin can delete
  assert.equal((await call('DELETE', `/api/tickets/${t1.body.id}`, null, agent)).status, 403);
  assert.equal((await call('DELETE', `/api/tickets/${t1.body.id}`, null, admin)).status, 204);
});

test('device CRUD with search and uniqueness', async () => {
  const agent = await login('agent@endpointops.dev', 'Agent@123');
  const admin = await login('admin@endpointops.dev', 'Admin@123');
  assert.equal((await call('GET', '/api/devices?q=macOS', null, agent)).body.total, 1);
  assert.equal((await call('GET', '/api/devices?status=offline', null, agent)).body.total, 1);
  const d = await call('POST', '/api/devices', { hostname: 'blr-lap-099', os: 'Windows 11' }, agent);
  assert.equal(d.status, 201);
  assert.equal((await call('POST', '/api/devices', { hostname: 'blr-lap-099' }, agent)).status, 409);
  assert.equal((await call('PUT', `/api/devices/${d.body.id}`, { hostname: 'blr-lap-099', status: 'offline' }, agent)).body.status, 'offline');
  assert.equal((await call('DELETE', `/api/devices/${d.body.id}`, null, agent)).status, 403);
  assert.equal((await call('DELETE', `/api/devices/${d.body.id}`, null, admin)).status, 204);
});

test('admin can change roles; invalid role rejected', async () => {
  const admin = await login('admin@endpointops.dev', 'Admin@123');
  const users = (await call('GET', '/api/users', null, admin)).body;
  const ravi = users.find(u => u.email === 'ravi@x.com');
  assert.equal((await call('PATCH', `/api/users/${ravi.id}/role`, { role: 'agent' }, admin)).status, 200);
  assert.equal((await call('PATCH', `/api/users/${ravi.id}/role`, { role: 'root' }, admin)).status, 400);
});
