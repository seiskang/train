"use strict";

const { DatabaseSync } = require("node:sqlite");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, "app.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    name TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

function ensureColumn(table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = cols.some((c) => c.name === column);
  if (!exists) db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}

ensureColumn("users", "email_verified", "email_verified INTEGER NOT NULL DEFAULT 0");
ensureColumn("users", "verification_token", "verification_token TEXT");
ensureColumn("users", "verification_expires_at", "verification_expires_at TEXT");

const ADMIN_EMAIL = "justice11419@naver.com";
const ADMIN_PASSWORD = "12345678";

function seedAdmin() {
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(ADMIN_EMAIL);
  if (!existing) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    db.prepare(
      "INSERT INTO users (email, password_hash, name, role, email_verified) VALUES (?, ?, ?, ?, 1)"
    ).run(ADMIN_EMAIL, hash, "관리자", "admin");
    console.log(`[seed] 관리자 계정 생성됨: ${ADMIN_EMAIL}`);
  } else {
    // 관리자 계정은 가입 절차를 거치지 않으므로 항상 인증된 상태로 유지한다.
    db.prepare("UPDATE users SET email_verified = 1 WHERE email = ?").run(ADMIN_EMAIL);
  }
}

seedAdmin();

module.exports = db;
