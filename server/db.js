"use strict";

const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const ADMIN_EMAIL = "justice11419@naver.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "kRtHoHxSJaz";

const connectionString = process.env.POSTGRES_URL || process.env.DATABASE_URL;

let pool = null;
function getPool() {
  if (!pool) {
    if (!connectionString) {
      throw new Error(
        "데이터베이스 연결 정보(POSTGRES_URL 또는 DATABASE_URL)가 설정되지 않았습니다. Vercel 프로젝트에 Postgres 스토리지를 연결해주세요."
      );
    }
    pool = new Pool({
      connectionString,
      ssl: connectionString.includes("sslmode=") ? undefined : { rejectUnauthorized: false }
    });
  }
  return pool;
}

async function query(text, params) {
  return getPool().query(text, params);
}

let schemaReady = null;

function ensureSchema() {
  if (!schemaReady) {
    schemaReady = (async () => {
      await query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          name TEXT,
          role TEXT NOT NULL DEFAULT 'user',
          email_verified INTEGER NOT NULL DEFAULT 0,
          verification_token TEXT,
          verification_expires_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      const existing = await query("SELECT id FROM users WHERE email = $1", [ADMIN_EMAIL]);
      if (existing.rows.length === 0) {
        const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
        await query(
          "INSERT INTO users (email, password_hash, name, role, email_verified) VALUES ($1, $2, $3, 'admin', 1)",
          [ADMIN_EMAIL, hash, "관리자"]
        );
      } else {
        await query("UPDATE users SET email_verified = 1 WHERE email = $1", [ADMIN_EMAIL]);
      }
    })();
  }
  return schemaReady;
}

async function getUserByEmail(email) {
  await ensureSchema();
  const { rows } = await query("SELECT * FROM users WHERE email = $1", [email]);
  return rows[0] || null;
}

async function getUserById(id) {
  await ensureSchema();
  const { rows } = await query("SELECT * FROM users WHERE id = $1", [id]);
  return rows[0] || null;
}

async function getUserByToken(token) {
  await ensureSchema();
  const { rows } = await query("SELECT * FROM users WHERE verification_token = $1", [token]);
  return rows[0] || null;
}

async function createUser(email, passwordHash, name) {
  await ensureSchema();
  const { rows } = await query(
    "INSERT INTO users (email, password_hash, name, role, email_verified) VALUES ($1, $2, $3, 'user', 0) RETURNING id",
    [email, passwordHash, name || null]
  );
  return rows[0].id;
}

async function setVerification(userId, token, expiresAt) {
  await ensureSchema();
  await query(
    "UPDATE users SET verification_token = $1, verification_expires_at = $2 WHERE id = $3",
    [token, expiresAt, userId]
  );
}

async function markVerified(userId) {
  await ensureSchema();
  await query(
    "UPDATE users SET email_verified = 1, verification_token = NULL, verification_expires_at = NULL WHERE id = $1",
    [userId]
  );
}

async function listUsers() {
  await ensureSchema();
  const { rows } = await query("SELECT id, email, name, role, created_at FROM users ORDER BY id");
  return rows;
}

module.exports = {
  ensureSchema,
  getUserByEmail,
  getUserById,
  getUserByToken,
  createUser,
  setVerification,
  markVerified,
  listUsers
};
