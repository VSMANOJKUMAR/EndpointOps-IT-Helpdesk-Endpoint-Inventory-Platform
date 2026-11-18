const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { createDb } = require('./db');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const STATUSES = ['open', 'in_progress', 'resolved', 'closed'];
const PRIORITIES = ['low', 'medium', 'high', 'critical'];
const DEVICE_STATUSES = ['healthy', 'needs_attention', 'offline'];

function createApp(db = createDb()) {
  const app = express();
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(express.json({ limit: '100kb' }));
  app.use(express.static(path.join(__dirname, '..', 'public')));

  const audit = (uid, action, entity, id) =>
    db.prepare('INSERT INTO audit_log (user_id,action,entity,entity_id) VALUES (?,?,?,?)').run(uid, action, entity, id);
  const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
  const str = (v, max = 500) => typeof v === 'string' && v.trim().length > 0 && v.length <= max;
  const page = q => {
    const limit = Math.min(Math.max(parseInt(q.limit) || 10, 1), 100);
    const p = Math.max(parseInt(q.page) || 1, 1);
    return { limit, offset: (p - 1) * limit, page: p };
  };

  // ---------- middleware ----------
  const auth = (req, res, next) => {
    const h = req.headers.authorization || '';
    try {
      req.user = jwt.verify(h.startsWith('Bearer ') ? h.slice(7) : '', SECRET);
      next();
    } catch { bad(res, 'Authentication required', 401); }
  };
  const requireRole = (...roles) => (req, res, next) =>
    roles.includes(req.user.role) ? next() : bad(res, 'Forbidden', 403);
  const isStaff = u => u.role === 'agent' || u.role === 'admin';

  // ---------- auth ----------
  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: process.env.NODE_ENV === 'test' ? 1000 : 20 });
  const sign = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, SECRET, { expiresIn: '8h' });

  app.post('/api/auth/register', loginLimiter, (req, res) => {
    const { name, email, password } = req.body || {};
    if (!str(name, 100) || !/^\S+@\S+\.\S+$/.test(email || '')) return bad(res, 'Valid name and email required');
    if (!str(password, 100) || password.length < 8) return bad(res, 'Password must be at least 8 characters');
    try {
      const r = db.prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)')
        .run(name.trim(), email.toLowerCase(), bcrypt.hashSync(password, 10));
      const user = { id: r.lastInsertRowid, name: name.trim(), role: 'user' };
      audit(user.id, 'register', 'user', user.id);
      res.status(201).json({ token: sign(user), user });
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) return bad(res, 'Email already registered', 409);
      throw e;
    }
  });

  app.post('/api/auth/login', loginLimiter, (req, res) => {
    const { email, password } = req.body || {};
    const u = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').toLowerCase());
    if (!u || !bcrypt.compareSync(String(password || ''), u.password_hash)) return bad(res, 'Invalid credentials', 401);
    audit(u.id, 'login', 'user', u.id);
    res.json({ token: sign(u), user: { id: u.id, name: u.name, role: u.role } });
  });

  app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

  // ---------- users (admin) ----------
  app.get('/api/users', auth, requireRole('agent', 'admin'), (req, res) =>
    res.json(db.prepare('SELECT id,name,email,role,created_at FROM users ORDER BY id').all()));

  app.patch('/api/users/:id/role', auth, requireRole('admin'), (req, res) => {
    const { role } = req.body || {};
    if (!['user', 'agent', 'admin'].includes(role)) return bad(res, 'Invalid role');
    const r = db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
    if (!r.changes) return bad(res, 'User not found', 404);
    audit(req.user.id, `role:${role}`, 'user', +req.params.id);
    res.json({ ok: true });
  });

  // ---------- devices ----------
  app.get('/api/devices', auth, requireRole('agent', 'admin'), (req, res) => {
    const { q, status } = req.query, { limit, offset, page: p } = page(req.query);
    const where = [], args = [];
    if (q) { where.push('(hostname LIKE ? OR os LIKE ? OR ip LIKE ?)'); args.push(...Array(3).fill(`%${q}%`)); }
    if (status) { where.push('status = ?'); args.push(status); }
    const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const total = db.prepare(`SELECT COUNT(*) c FROM devices ${w}`).get(...args).c;
    const items = db.prepare(`SELECT * FROM devices ${w} ORDER BY hostname LIMIT ? OFFSET ?`).all(...args, limit, offset);
    res.json({ items, total, page: p, limit });
  });

  const deviceBody = b => str(b.hostname, 100) && (!b.status || DEVICE_STATUSES.includes(b.status));

  app.post('/api/devices', auth, requireRole('agent', 'admin'), (req, res) => {
    const b = req.body || {};
    if (!deviceBody(b)) return bad(res, 'Valid hostname (and status) required');
    try {
      const r = db.prepare('INSERT INTO devices (hostname,os,ip,status) VALUES (?,?,?,?)')
        .run(b.hostname.trim(), b.os || null, b.ip || null, b.status || 'healthy');
      audit(req.user.id, 'create', 'device', r.lastInsertRowid);
      res.status(201).json(db.prepare('SELECT * FROM devices WHERE id=?').get(r.lastInsertRowid));
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) return bad(res, 'Hostname already exists', 409);
      throw e;
    }
  });

  app.put('/api/devices/:id', auth, requireRole('agent', 'admin'), (req, res) => {
    const b = req.body || {};
    if (!deviceBody(b)) return bad(res, 'Valid hostname (and status) required');
    const r = db.prepare('UPDATE devices SET hostname=?, os=?, ip=?, status=COALESCE(?,status), last_seen=CURRENT_TIMESTAMP WHERE id=?')
      .run(b.hostname.trim(), b.os || null, b.ip || null, b.status || null, req.params.id);
    if (!r.changes) return bad(res, 'Device not found', 404);
    audit(req.user.id, 'update', 'device', +req.params.id);
    res.json(db.prepare('SELECT * FROM devices WHERE id=?').get(req.params.id));
  });

  app.delete('/api/devices/:id', auth, requireRole('admin'), (req, res) => {
    const r = db.prepare('DELETE FROM devices WHERE id=?').run(req.params.id);
    if (!r.changes) return bad(res, 'Device not found', 404);
    audit(req.user.id, 'delete', 'device', +req.params.id);
    res.status(204).end();
  });

  // ---------- tickets ----------
  const canSee = (u, t) => isStaff(u) || t.creator_id === u.id;
  const ticketSelect = `SELECT t.*, c.name creator_name, a.name assignee_name, d.hostname device_hostname
    FROM tickets t JOIN users c ON c.id=t.creator_id LEFT JOIN users a ON a.id=t.assignee_id
    LEFT JOIN devices d ON d.id=t.device_id`;

  app.get('/api/tickets', auth, (req, res) => {
    const { q, status, priority, sort = 'created_at', order = 'desc' } = req.query;
    const { limit, offset, page: p } = page(req.query);
    const where = [], args = [];
    if (!isStaff(req.user)) { where.push('t.creator_id = ?'); args.push(req.user.id); }
    if (q) { where.push('(t.title LIKE ? OR t.description LIKE ?)'); args.push(`%${q}%`, `%${q}%`); }
    if (status) { where.push('t.status = ?'); args.push(status); }
    if (priority) { where.push('t.priority = ?'); args.push(priority); }
    const col = { created_at: 't.created_at', priority: 't.priority', status: 't.status', title: 't.title' }[sort] || 't.created_at';
    const dir = order === 'asc' ? 'ASC' : 'DESC';
    const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const total = db.prepare(`SELECT COUNT(*) c FROM tickets t ${w}`).get(...args).c;
    const items = db.prepare(`${ticketSelect} ${w} ORDER BY ${col} ${dir}, t.id DESC LIMIT ? OFFSET ?`).all(...args, limit, offset);
    res.json({ items, total, page: p, limit });
  });

  app.post('/api/tickets', auth, (req, res) => {
    const { title, description, priority = 'medium', device_id = null } = req.body || {};
    if (!str(title, 200) || !str(description, 5000)) return bad(res, 'Title and description required');
    if (!PRIORITIES.includes(priority)) return bad(res, 'Invalid priority');
    if (device_id && !db.prepare('SELECT 1 FROM devices WHERE id=?').get(device_id)) return bad(res, 'Device not found', 404);
    const r = db.prepare('INSERT INTO tickets (title,description,priority,creator_id,device_id) VALUES (?,?,?,?,?)')
      .run(title.trim(), description.trim(), priority, req.user.id, device_id);
    audit(req.user.id, 'create', 'ticket', r.lastInsertRowid);
    res.status(201).json(db.prepare(`${ticketSelect} WHERE t.id=?`).get(r.lastInsertRowid));
  });

  app.get('/api/tickets/:id', auth, (req, res) => {
    const t = db.prepare(`${ticketSelect} WHERE t.id=?`).get(req.params.id);
    if (!t || !canSee(req.user, t)) return bad(res, 'Ticket not found', 404);
    t.comments = db.prepare(`SELECT c.*, u.name author_name FROM comments c JOIN users u ON u.id=c.author_id
      WHERE ticket_id=? ORDER BY c.id`).all(t.id);
    res.json(t);
  });

  app.patch('/api/tickets/:id', auth, (req, res) => {
    const t = db.prepare('SELECT * FROM tickets WHERE id=?').get(req.params.id);
    if (!t || !canSee(req.user, t)) return bad(res, 'Ticket not found', 404);
    const b = req.body || {};
    if (!isStaff(req.user) && ('status' in b || 'assignee_id' in b || 'priority' in b))
      return bad(res, 'Only agents can change status, priority or assignee', 403);
    if (b.status && !STATUSES.includes(b.status)) return bad(res, 'Invalid status');
    if (b.priority && !PRIORITIES.includes(b.priority)) return bad(res, 'Invalid priority');
    if (b.assignee_id && !db.prepare("SELECT 1 FROM users WHERE id=? AND role IN ('agent','admin')").get(b.assignee_id))
      return bad(res, 'Assignee must be an agent or admin');
    const n = { ...t, ...b };
    if (b.title !== undefined && !str(b.title, 200)) return bad(res, 'Invalid title');
    db.prepare("UPDATE tickets SET title=?,description=?,status=?,priority=?,assignee_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(n.title, n.description, n.status, n.priority, n.assignee_id ?? null, t.id);
    audit(req.user.id, 'update', 'ticket', t.id);
    res.json(db.prepare(`${ticketSelect} WHERE t.id=?`).get(t.id));
  });

  app.delete('/api/tickets/:id', auth, requireRole('admin'), (req, res) => {
    const r = db.prepare('DELETE FROM tickets WHERE id=?').run(req.params.id);
    if (!r.changes) return bad(res, 'Ticket not found', 404);
    audit(req.user.id, 'delete', 'ticket', +req.params.id);
    res.status(204).end();
  });

  app.post('/api/tickets/:id/comments', auth, (req, res) => {
    const t = db.prepare('SELECT * FROM tickets WHERE id=?').get(req.params.id);
    if (!t || !canSee(req.user, t)) return bad(res, 'Ticket not found', 404);
    if (!str(req.body?.body, 2000)) return bad(res, 'Comment body required');
    const r = db.prepare('INSERT INTO comments (ticket_id,author_id,body) VALUES (?,?,?)').run(t.id, req.user.id, req.body.body.trim());
    db.prepare('UPDATE tickets SET updated_at=CURRENT_TIMESTAMP WHERE id=?').run(t.id);
    audit(req.user.id, 'comment', 'ticket', t.id);
    res.status(201).json({ id: r.lastInsertRowid });
  });

  // ---------- dashboard & audit ----------
  app.get('/api/stats', auth, (req, res) => {
    const scope = isStaff(req.user) ? ['', []] : ['WHERE creator_id = ?', [req.user.id]];
    const by = col => Object.fromEntries(db.prepare(`SELECT ${col} k, COUNT(*) c FROM tickets ${scope[0]} GROUP BY ${col}`).all(...scope[1]).map(r => [r.k, r.c]));
    const out = { ticketsByStatus: by('status'), ticketsByPriority: by('priority') };
    if (isStaff(req.user))
      out.devicesByStatus = Object.fromEntries(db.prepare('SELECT status k, COUNT(*) c FROM devices GROUP BY status').all().map(r => [r.k, r.c]));
    res.json(out);
  });

  app.get('/api/audit', auth, requireRole('admin'), (req, res) =>
    res.json(db.prepare(`SELECT a.*, u.name user_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
      ORDER BY a.id DESC LIMIT 100`).all()));

  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
  app.use('/api', (req, res) => bad(res, 'Not found', 404));
  app.use((err, req, res, next) => { console.error(err); bad(res, 'Internal server error', 500); });
  return app;
}
module.exports = { createApp };
