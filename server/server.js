"use strict";

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");

const VERIFY_TTL_MS = 30 * 60 * 1000; // 인증 링크 유효 시간: 30분

function issueVerification(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + VERIFY_TTL_MS).toISOString();
  db.prepare("UPDATE users SET verification_token = ?, verification_expires_at = ? WHERE id = ?").run(
    token,
    expiresAt,
    userId
  );
  return token;
}

function sendVerificationEmail(req, email, token) {
  const verifyUrl = `${req.protocol}://${req.get("host")}/api/verify-email?token=${token}`;
  // TODO: 실제 서비스에서는 여기서 SMTP(nodemailer 등)로 실제 메일을 발송한다.
  // 지금은 개발 모드 시뮬레이션으로 콘솔에만 출력하고, 링크를 응답으로 함께 내려준다.
  console.log(`[email:simulated] ${email} 님에게 인증 메일 발송 → ${verifyUrl}`);
  return verifyUrl;
}

const app = express();

app.use(express.json());
app.use(
  session({
    secret: "class-manager-dev-secret-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" }
  })
);
const DASHBOARD_FILE = path.join(__dirname, "..", "index.html");
app.get("/", (req, res) => res.sendFile(DASHBOARD_FILE));

function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role };
}

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.post("/api/signup", (req, res) => {
  const { email, password, name } = req.body || {};
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "올바른 이메일을 입력해주세요." });
  }
  if (typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ error: "비밀번호는 8자 이상이어야 합니다." });
  }
  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (exists) {
    return res.status(409).json({ error: "이미 가입된 이메일입니다." });
  }
  const hash = bcrypt.hashSync(password, 10);
  const info = db
    .prepare("INSERT INTO users (email, password_hash, name, role, email_verified) VALUES (?, ?, ?, 'user', 0)")
    .run(email, hash, name || null);
  const token = issueVerification(info.lastInsertRowid);
  const devVerifyUrl = sendVerificationEmail(req, email, token);
  // 이메일 인증 전에는 세션을 만들지 않는다 — 인증 완료 후에만 로그인 가능.
  res.status(201).json({ pendingVerification: true, email, devVerifyUrl });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email || "");
  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
    return res.status(401).json({ error: "이메일 또는 비밀번호가 올바르지 않습니다." });
  }
  if (!user.email_verified) {
    return res.status(403).json({ error: "이메일 인증이 완료되지 않았습니다. 메일함에서 인증을 완료해주세요.", unverified: true });
  }
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.get("/api/verify-email", (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send("인증 토큰이 없습니다.");
  const user = db.prepare("SELECT * FROM users WHERE verification_token = ?").get(token);
  if (!user) return res.status(400).send("유효하지 않은 인증 링크입니다.");
  if (user.verification_expires_at && new Date(user.verification_expires_at).getTime() < Date.now()) {
    return res.status(400).send("인증 링크가 만료되었습니다. 인증 메일을 다시 요청해주세요.");
  }
  db.prepare(
    "UPDATE users SET email_verified = 1, verification_token = NULL, verification_expires_at = NULL WHERE id = ?"
  ).run(user.id);
  req.session.userId = user.id;
  res.redirect("/?verified=1");
});

app.post("/api/resend-verification", (req, res) => {
  const { email } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email || "");
  if (!user) return res.status(404).json({ error: "가입된 이메일이 아닙니다." });
  if (user.email_verified) return res.status(400).json({ error: "이미 인증이 완료된 계정입니다." });
  const token = issueVerification(user.id);
  const devVerifyUrl = sendVerificationEmail(req, email, token);
  res.json({ email, devVerifyUrl });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  const user = req.session.userId
    ? db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId)
    : null;
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  res.json({ user: publicUser(user) });
});

function requireAdmin(req, res, next) {
  const user = req.session.userId
    ? db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId)
    : null;
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  if (user.role !== "admin") return res.status(403).json({ error: "관리자만 접근할 수 있습니다." });
  req.user = user;
  next();
}

app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = db.prepare("SELECT id, email, name, role, created_at FROM users ORDER BY id").all();
  res.json({ users });
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`회원가입 DB 서버 실행 중: http://localhost:${PORT}`);
});
