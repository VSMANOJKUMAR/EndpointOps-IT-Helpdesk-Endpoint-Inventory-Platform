const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

function createDb(file = process.env.DB_FILE || 'data.db') {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','agent','admin')),
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY, hostname TEXT NOT NULL UNIQUE, os TEXT, ip TEXT,
      status TEXT NOT NULL DEFAULT 'healthy' CHECK (status IN ('healthy','needs_attention','offline')),
      owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      last_seen TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved','closed')),
      priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','critical')),
      creator_id INTEGER NOT NULL REFERENCES users(id),
      assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY, ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
      author_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, entity TEXT, entity_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
    CREATE INDEX IF NOT EXISTS idx_tickets_creator ON tickets(creator_id);
    CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
  `);
  if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
    const ins = db.prepare('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)');
    ins.run('Admin', 'admin@endpointops.dev', bcrypt.hashSync('Admin@123', 10), 'admin');
    ins.run('Asha Agent', 'agent@endpointops.dev', bcrypt.hashSync('Agent@123', 10), 'agent');
    const dev = db.prepare('INSERT INTO devices (hostname,os,ip,status) VALUES (?,?,?,?)');
    [['blr-lap-001','Windows 11','10.0.1.21','healthy'],['blr-lap-002','macOS 14','10.0.1.22','needs_attention'],
     ['blr-srv-010','Ubuntu 22.04','10.0.2.10','healthy'],['blr-lap-003','Windows 10','10.0.1.23','offline']]
      .forEach(d => dev.run(...d));
  }
  return db;
}
module.exports = { createDb };
