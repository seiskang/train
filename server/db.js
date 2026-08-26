"use strict";

const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const ADMIN_EMAIL = "justice11419@naver.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

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
      await query("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT");
      await query("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires_at TIMESTAMPTZ");
      await query(`
        CREATE TABLE IF NOT EXISTS students (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE
        )
      `);
      const STUDENT_SEED = [
        ["s1", "Emily Carter", "emily.carter@example.com"],
        ["s2", "Nguyen Thi Mai", "nguyen.mai@example.com"],
        ["s3", "Kenji Sato", "kenji.sato@example.com"],
        ["s4", "Sofia Rossi", "sofia.rossi@example.com"],
        ["s5", "Daniel Kim", "daniel.kim@example.com"],
        ["s6", "Aisha Rahman", "aisha.rahman@example.com"]
      ];
      for (const [id, name, email] of STUDENT_SEED) {
        await query(
          "INSERT INTO students (id, name, email) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
          [id, name, email]
        );
      }
      await query(`
        CREATE TABLE IF NOT EXISTS assignments (
          id SERIAL PRIMARY KEY,
          student_id TEXT NOT NULL REFERENCES students(id),
          title TEXT NOT NULL,
          file_name TEXT NOT NULL,
          mime_type TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          blob_url TEXT NOT NULL,
          blob_pathname TEXT NOT NULL,
          uploaded_by INTEGER REFERENCES users(id),
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      await query(`
        CREATE TABLE IF NOT EXISTS materials (
          id SERIAL PRIMARY KEY,
          title TEXT NOT NULL,
          file_name TEXT NOT NULL,
          mime_type TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          blob_url TEXT NOT NULL,
          blob_pathname TEXT NOT NULL,
          uploaded_by INTEGER REFERENCES users(id),
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      const existing = await query("SELECT id FROM users WHERE email = $1", [ADMIN_EMAIL]);
      if (existing.rows.length === 0 && ADMIN_PASSWORD) {
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

async function getUserByResetToken(token) {
  await ensureSchema();
  const { rows } = await query("SELECT * FROM users WHERE reset_token = $1", [token]);
  return rows[0] || null;
}

async function setResetToken(userId, token, expiresAt) {
  await ensureSchema();
  await query("UPDATE users SET reset_token = $1, reset_expires_at = $2 WHERE id = $3", [token, expiresAt, userId]);
}

async function resetPassword(userId, passwordHash) {
  await ensureSchema();
  await query(
    "UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires_at = NULL WHERE id = $2",
    [passwordHash, userId]
  );
}

async function listUsers() {
  await ensureSchema();
  const { rows } = await query("SELECT id, email, name, role, created_at FROM users ORDER BY id");
  return rows;
}

async function listMaterials() {
  await ensureSchema();
  const { rows } = await query(`
    SELECT m.id, m.title, m.file_name, m.mime_type, m.size_bytes, m.blob_url, m.created_at, u.name AS uploaded_by_name, u.email AS uploaded_by_email
    FROM materials m
    LEFT JOIN users u ON u.id = m.uploaded_by
    ORDER BY m.created_at DESC
  `);
  return rows;
}

async function createMaterial({ title, fileName, mimeType, sizeBytes, blobUrl, blobPathname, uploadedBy }) {
  await ensureSchema();
  const { rows } = await query(
    `INSERT INTO materials (title, file_name, mime_type, size_bytes, blob_url, blob_pathname, uploaded_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, title, file_name, mime_type, size_bytes, blob_url, created_at`,
    [title, fileName, mimeType, sizeBytes, blobUrl, blobPathname, uploadedBy]
  );
  return rows[0];
}

async function getMaterialById(id) {
  await ensureSchema();
  const { rows } = await query("SELECT * FROM materials WHERE id = $1", [id]);
  return rows[0] || null;
}

async function deleteMaterial(id) {
  await ensureSchema();
  await query("DELETE FROM materials WHERE id = $1", [id]);
}

async function listStudents() {
  await ensureSchema();
  const { rows } = await query("SELECT id, name, email FROM students ORDER BY id");
  return rows;
}

async function getStudentById(id) {
  await ensureSchema();
  const { rows } = await query("SELECT id, name, email FROM students WHERE id = $1", [id]);
  return rows[0] || null;
}

async function getStudentByEmail(email) {
  await ensureSchema();
  const { rows } = await query("SELECT id, name, email FROM students WHERE email = $1", [email]);
  return rows[0] || null;
}

async function listAssignments(studentId) {
  await ensureSchema();
  const { rows } = await query(
    "SELECT id, student_id, title, file_name, mime_type, size_bytes, blob_url, created_at FROM assignments WHERE student_id = $1 ORDER BY created_at DESC",
    [studentId]
  );
  return rows;
}

async function createAssignment({ studentId, title, fileName, mimeType, sizeBytes, blobUrl, blobPathname, uploadedBy }) {
  await ensureSchema();
  const { rows } = await query(
    `INSERT INTO assignments (student_id, title, file_name, mime_type, size_bytes, blob_url, blob_pathname, uploaded_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, student_id, title, file_name, mime_type, size_bytes, blob_url, created_at`,
    [studentId, title, fileName, mimeType, sizeBytes, blobUrl, blobPathname, uploadedBy]
  );
  return rows[0];
}

async function getAssignmentById(id) {
  await ensureSchema();
  const { rows } = await query("SELECT * FROM assignments WHERE id = $1", [id]);
  return rows[0] || null;
}

async function renameAssignment(id, title) {
  await ensureSchema();
  const { rows } = await query(
    "UPDATE assignments SET title = $1 WHERE id = $2 RETURNING id, student_id, title, file_name, mime_type, size_bytes, blob_url, created_at",
    [title, id]
  );
  return rows[0] || null;
}

async function deleteAssignment(id) {
  await ensureSchema();
  await query("DELETE FROM assignments WHERE id = $1", [id]);
}

module.exports = {
  ensureSchema,
  getUserByEmail,
  getUserById,
  getUserByToken,
  createUser,
  setVerification,
  markVerified,
  getUserByResetToken,
  setResetToken,
  resetPassword,
  listUsers,
  listMaterials,
  createMaterial,
  getMaterialById,
  deleteMaterial,
  listStudents,
  getStudentById,
  getStudentByEmail,
  listAssignments,
  createAssignment,
  getAssignmentById,
  renameAssignment,
  deleteAssignment
};
