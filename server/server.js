"use strict";

const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const multer = require("multer");
const { put, del } = require("@vercel/blob");
const db = require("./db");

const MATERIAL_MAX_BYTES = 20 * 1024 * 1024; // 교안 업로드 용량 제한: 20MB
const ALLOWED_MATERIAL_TYPES = {
  ".md": "text/markdown",
  ".pdf": "application/pdf"
};
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MATERIAL_MAX_BYTES } });

const VERIFY_TTL_MS = 30 * 60 * 1000; // 인증 링크 유효 시간: 30분
const SESSION_TTL_MS = 400 * 24 * 60 * 60 * 1000; // 로그인 유지 시간: 400일(브라우저가 허용하는 쿠키 최대 기간) — 직접 로그아웃하기 전까지 로그인 유지
const JWT_SECRET = process.env.JWT_SECRET || "class-manager-dev-secret-change-in-production";
const COOKIE_NAME = "session";

async function issueVerification(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + VERIFY_TTL_MS).toISOString();
  await db.setVerification(userId, token, expiresAt);
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
app.use(cookieParser());

function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role };
}

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function setSessionCookie(res, userId) {
  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "400d" });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_TTL_MS
  });
}

async function getSessionUser(req) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return await db.getUserById(payload.userId);
  } catch {
    return null;
  }
}

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "올바른 이메일을 입력해주세요." });
    }
    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ error: "비밀번호는 8자 이상이어야 합니다." });
    }
    const exists = await db.getUserByEmail(email);
    if (exists) {
      return res.status(409).json({ error: "이미 가입된 이메일입니다." });
    }
    const hash = bcrypt.hashSync(password, 10);
    const userId = await db.createUser(email, hash, name);
    const token = await issueVerification(userId);
    const devVerifyUrl = sendVerificationEmail(req, email, token);
    // 이메일 인증 전에는 세션을 만들지 않는다 — 인증 완료 후에만 로그인 가능.
    res.status(201).json({ pendingVerification: true, email, devVerifyUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await db.getUserByEmail(email || "");
    if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
      return res.status(401).json({ error: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }
    if (!user.email_verified) {
      return res.status(403).json({ error: "이메일 인증이 완료되지 않았습니다. 메일함에서 인증을 완료해주세요.", unverified: true });
    }
    setSessionCookie(res, user.id);
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.get("/api/verify-email", async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(400).send("인증 토큰이 없습니다.");
    const user = await db.getUserByToken(token);
    if (!user) return res.status(400).send("유효하지 않은 인증 링크입니다.");
    if (user.verification_expires_at && new Date(user.verification_expires_at).getTime() < Date.now()) {
      return res.status(400).send("인증 링크가 만료되었습니다. 인증 메일을 다시 요청해주세요.");
    }
    await db.markVerified(user.id);
    setSessionCookie(res, user.id);
    res.redirect("/?verified=1");
  } catch (err) {
    console.error(err);
    res.status(500).send("서버 오류가 발생했습니다.");
  }
});

app.post("/api/resend-verification", async (req, res) => {
  try {
    const { email } = req.body || {};
    const user = await db.getUserByEmail(email || "");
    if (!user) return res.status(404).json({ error: "가입된 이메일이 아닙니다." });
    if (user.email_verified) return res.status(400).json({ error: "이미 인증이 완료된 계정입니다." });
    const token = await issueVerification(user.id);
    const devVerifyUrl = sendVerificationEmail(req, email, token);
    res.json({ email, devVerifyUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body || {};
    const user = await db.getUserByEmail(email || "");
    if (!user) return res.status(404).json({ error: "가입된 이메일이 아닙니다." });
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + VERIFY_TTL_MS).toISOString();
    await db.setResetToken(user.id, token, expiresAt);
    const resetUrl = `${req.protocol}://${req.get("host")}/?resetToken=${token}`;
    // TODO: 실제 서비스에서는 여기서 SMTP(nodemailer 등)로 실제 메일을 발송한다.
    console.log(`[email:simulated] ${email} 님에게 비밀번호 재설정 메일 발송 → ${resetUrl}`);
    res.json({ email, devResetUrl: resetUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ error: "비밀번호는 8자 이상이어야 합니다." });
    }
    const user = await db.getUserByResetToken(token || "");
    if (!user) return res.status(400).json({ error: "유효하지 않은 링크입니다." });
    if (user.reset_expires_at && new Date(user.reset_expires_at).getTime() < Date.now()) {
      return res.status(400).json({ error: "링크가 만료되었습니다. 다시 요청해주세요." });
    }
    const hash = bcrypt.hashSync(password, 10);
    await db.resetPassword(user.id, hash);
    setSessionCookie(res, user.id);
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get("/api/me", async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  res.json({ user: publicUser(user) });
});

async function requireAdmin(req, res, next) {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  if (user.role !== "admin") return res.status(403).json({ error: "관리자만 접근할 수 있습니다." });
  req.user = user;
  next();
}

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const users = await db.listUsers();
  res.json({ users });
});

app.get("/api/materials", async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  try {
    const materials = await db.listMaterials();
    res.json({ materials });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/materials", requireAdmin, (req, res) => {
  upload.single("file")(req, res, async (err) => {
    if (err) {
      const message = err.code === "LIMIT_FILE_SIZE" ? "파일 용량은 20MB 이하만 업로드할 수 있습니다." : "업로드에 실패했습니다.";
      return res.status(400).json({ error: message });
    }
    try {
      const file = req.file;
      if (!file) return res.status(400).json({ error: "파일을 선택해주세요." });
      const ext = (file.originalname.match(/\.[^.]+$/) || [""])[0].toLowerCase();
      const mimeType = ALLOWED_MATERIAL_TYPES[ext];
      if (!mimeType) return res.status(400).json({ error: "md 또는 pdf 파일만 업로드할 수 있습니다." });

      const blob = await put(`materials/${crypto.randomUUID()}${ext}`, file.buffer, {
        access: "public",
        contentType: mimeType
      });

      const material = await db.createMaterial({
        title: (req.body.title || file.originalname.replace(ext, "")).trim() || file.originalname,
        fileName: file.originalname,
        mimeType,
        sizeBytes: file.size,
        blobUrl: blob.url,
        blobPathname: blob.pathname,
        uploadedBy: req.user.id
      });
      res.status(201).json({ material });
    } catch (uploadErr) {
      console.error(uploadErr);
      res.status(500).json({ error: "서버 오류가 발생했습니다." });
    }
  });
});

app.delete("/api/materials/:id", requireAdmin, async (req, res) => {
  try {
    const material = await db.getMaterialById(req.params.id);
    if (!material) return res.status(404).json({ error: "찾을 수 없습니다." });
    await del(material.blob_pathname).catch(() => {});
    await db.deleteMaterial(material.id);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 8000;
  app.listen(PORT, () => {
    console.log(`회원가입 DB 서버 실행 중: http://localhost:${PORT}`);
  });
}
