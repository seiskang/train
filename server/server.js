"use strict";

const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const multer = require("multer");
const { put, del } = require("@vercel/blob");
const db = require("./db");
const dashboard = require("./dashboard");

const MATERIAL_MAX_BYTES = 20 * 1024 * 1024; // 교안 업로드 용량 제한: 20MB
const ALLOWED_MATERIAL_TYPES = {
  ".md": "text/markdown",
  ".pdf": "application/pdf"
};
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MATERIAL_MAX_BYTES } });

const VERIFY_TTL_MS = 30 * 60 * 1000; // 인증 링크 유효 시간: 30분
const SESSION_TTL_MS = 400 * 24 * 60 * 60 * 1000; // 로그인 유지 시간: 400일(브라우저가 허용하는 쿠키 최대 기간) — 직접 로그아웃하기 전까지 로그인 유지
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET 환경변수가 설정되지 않았습니다.");
}
const COOKIE_NAME = "session";

const KAKAO_CLIENT_ID = process.env.KAKAO_CLIENT_ID;
const KAKAO_CLIENT_SECRET = process.env.KAKAO_CLIENT_SECRET;
const WECHAT_APP_ID = process.env.WECHAT_APP_ID;
const WECHAT_APP_SECRET = process.env.WECHAT_APP_SECRET;

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_EMAIL_DOMAIN = process.env.RESEND_EMAIL_DOMAIN;
const MAIL_FROM = RESEND_EMAIL_DOMAIN ? `세이스강 클래스 매니저 <noreply@${RESEND_EMAIL_DOMAIN}>` : null;

async function sendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY || !MAIL_FROM) return false;
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html })
    });
    if (!res.ok) {
      console.error("[email] 발송 실패:", res.status, await res.text().catch(() => ""));
      return false;
    }
    return true;
  } catch (err) {
    console.error("[email] 발송 오류:", err);
    return false;
  }
}

async function issueVerification(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + VERIFY_TTL_MS).toISOString();
  await db.setVerification(userId, token, expiresAt);
  return token;
}

function sendVerificationEmail(req, email, token) {
  const verifyUrl = `${req.protocol}://${req.get("host")}/api/verify-email?token=${token}`;
  sendEmail({
    to: email,
    subject: "[한국어 수업 관리] 이메일 인증을 완료해주세요",
    html: `<p>안녕하세요,</p><p>아래 버튼을 눌러 이메일 인증을 완료해주세요. (30분간 유효)</p>` +
      `<p><a href="${verifyUrl}" style="display:inline-block;padding:10px 20px;background:#1e3a8a;color:#fff;border-radius:6px;text-decoration:none">이메일 인증하기</a></p>` +
      `<p>버튼이 안 눌리면 이 링크를 복사해서 브라우저에 붙여넣으세요:<br>${verifyUrl}</p>`
  }).then(function (sent) {
    console.log(`[email] ${email} 님에게 인증 메일 ${sent ? "발송됨" : "발송 실패(콘솔 링크로 대체)"} → ${verifyUrl}`);
  });
  return verifyUrl;
}

const app = express();

app.set("trust proxy", true);
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
    const { email, password, name, agreeTerms, confirmAge } = req.body || {};
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "올바른 이메일을 입력해주세요." });
    }
    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ error: "비밀번호는 8자 이상이어야 합니다." });
    }
    if (agreeTerms !== true) {
      return res.status(400).json({ error: "이용약관 및 개인정보처리방침에 동의해야 가입할 수 있습니다." });
    }
    if (confirmAge !== true) {
      return res.status(400).json({ error: "만 14세 이상만 가입할 수 있습니다." });
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

app.get("/api/auth/kakao", (req, res) => {
  if (!KAKAO_CLIENT_ID) return res.status(503).send("카카오 로그인이 아직 설정되지 않았습니다.");
  const redirectUri = `${req.protocol}://${req.get("host")}/api/auth/kakao/callback`;
  const url = "https://kauth.kakao.com/oauth/authorize?" + new URLSearchParams({
    client_id: KAKAO_CLIENT_ID, redirect_uri: redirectUri, response_type: "code"
  });
  res.redirect(url);
});

app.get("/api/auth/kakao/callback", async (req, res) => {
  if (!KAKAO_CLIENT_ID) return res.status(503).send("카카오 로그인이 아직 설정되지 않았습니다.");
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send("인증 코드가 없습니다.");
    const redirectUri = `${req.protocol}://${req.get("host")}/api/auth/kakao/callback`;

    const tokenParams = new URLSearchParams({
      grant_type: "authorization_code", client_id: KAKAO_CLIENT_ID, redirect_uri: redirectUri, code
    });
    if (KAKAO_CLIENT_SECRET) tokenParams.set("client_secret", KAKAO_CLIENT_SECRET);

    const tokenRes = await fetch("https://kauth.kakao.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: tokenParams
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.error("카카오 토큰 발급 실패:", tokenData);
      return res.status(502).send("카카오 로그인에 실패했습니다.");
    }

    const profileRes = await fetch("https://kapi.kakao.com/v2/user/me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileRes.json();
    const kakaoId = String(profile.id);
    const account = profile.kakao_account || {};
    const email = account.email || null;
    const name = (account.profile && account.profile.nickname) || null;

    let user = await db.getUserByKakaoId(kakaoId);
    if (!user && email) user = await db.getUserByEmail(email);
    if (!user) {
      user = await db.createOAuthUser({ email: email || `kakao_${kakaoId}@kakao.local`, name, kakaoId });
    } else if (!user.kakao_id) {
      await db.linkKakaoId(user.id, kakaoId);
    }

    setSessionCookie(res, user.id);
    res.redirect("/");
  } catch (err) {
    console.error(err);
    res.status(500).send("카카오 로그인 중 오류가 발생했습니다.");
  }
});

app.get("/api/auth/wechat", (req, res) => {
  if (!WECHAT_APP_ID) return res.status(503).send("위챗 로그인이 아직 설정되지 않았습니다.");
  const redirectUri = `${req.protocol}://${req.get("host")}/api/auth/wechat/callback`;
  const url = "https://open.weixin.qq.com/connect/qrconnect?" + new URLSearchParams({
    appid: WECHAT_APP_ID, redirect_uri: redirectUri, response_type: "code", scope: "snsapi_login", state: "login"
  }) + "#wechat_redirect";
  res.redirect(url);
});

app.get("/api/auth/wechat/callback", async (req, res) => {
  if (!WECHAT_APP_ID) return res.status(503).send("위챗 로그인이 아직 설정되지 않았습니다.");
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send("인증 코드가 없습니다.");

    const tokenUrl = "https://api.weixin.qq.com/sns/oauth2/access_token?" + new URLSearchParams({
      appid: WECHAT_APP_ID, secret: WECHAT_APP_SECRET, code, grant_type: "authorization_code"
    });
    const tokenRes = await fetch(tokenUrl);
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.error("위챗 토큰 발급 실패:", tokenData);
      return res.status(502).send("위챗 로그인에 실패했습니다.");
    }

    const profileUrl = "https://api.weixin.qq.com/sns/userinfo?" + new URLSearchParams({
      access_token: tokenData.access_token, openid: tokenData.openid
    });
    const profileRes = await fetch(profileUrl);
    const profile = await profileRes.json();
    const wechatId = tokenData.openid;
    const name = profile.nickname || null;

    let user = await db.getUserByWechatId(wechatId);
    if (!user) {
      user = await db.createOAuthUser({ email: `wechat_${wechatId}@wechat.local`, name, wechatId });
    }

    setSessionCookie(res, user.id);
    res.redirect("/");
  } catch (err) {
    console.error(err);
    res.status(500).send("위챗 로그인 중 오류가 발생했습니다.");
  }
});

app.get("/api/auth/providers", (req, res) => {
  res.json({ kakao: !!KAKAO_CLIENT_ID, wechat: !!WECHAT_APP_ID });
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
    sendEmail({
      to: email,
      subject: "[한국어 수업 관리] 비밀번호 재설정",
      html: `<p>안녕하세요,</p><p>아래 버튼을 눌러 새 비밀번호를 설정해주세요. (30분간 유효)</p>` +
        `<p><a href="${resetUrl}" style="display:inline-block;padding:10px 20px;background:#1e3a8a;color:#fff;border-radius:6px;text-decoration:none">비밀번호 재설정하기</a></p>` +
        `<p>버튼이 안 눌리면 이 링크를 복사해서 브라우저에 붙여넣으세요:<br>${resetUrl}</p>` +
        `<p>본인이 요청하지 않았다면 이 메일을 무시해주세요.</p>`
    }).then(function (sent) {
      console.log(`[email] ${email} 님에게 재설정 메일 ${sent ? "발송됨" : "발송 실패(콘솔 링크로 대체)"} → ${resetUrl}`);
    });
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

async function resolveStudentAccess(user, studentId) {
  if (user.role === "admin") return { canView: true, canManage: false };
  const me = await db.getStudentByEmail(user.email);
  const isOwner = !!(me && me.id === studentId);
  return { canView: isOwner, canManage: isOwner };
}

app.get("/api/students", requireAdmin, async (req, res) => {
  try {
    const students = await db.listStudents();
    res.json({ students });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.patch("/api/students/:id", requireAdmin, async (req, res) => {
  try {
    const email = (req.body.email || "").trim();
    if (!isValidEmail(email)) return res.status(400).json({ error: "올바른 이메일을 입력해주세요." });
    const updated = await db.updateStudentEmail(req.params.id, email);
    if (!updated) return res.status(404).json({ error: "찾을 수 없습니다." });
    res.json({ student: updated });
  } catch (err) {
    if (err && err.code === "23505") {
      return res.status(409).json({ error: "이미 다른 수강생이 사용 중인 이메일입니다." });
    }
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.get("/api/students/me", async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  try {
    const student = await db.getStudentByEmail(user.email);
    res.json({ student });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.get("/api/assignments", async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  const studentId = req.query.studentId;
  if (!studentId) return res.status(400).json({ error: "studentId가 필요합니다." });
  try {
    const access = await resolveStudentAccess(user, studentId);
    if (!access.canView) return res.status(403).json({ error: "열람 권한이 없습니다." });
    const assignments = await db.listAssignments(studentId);
    res.json({ assignments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/assignments", (req, res) => {
  upload.single("file")(req, res, async (err) => {
    if (err) {
      const message = err.code === "LIMIT_FILE_SIZE" ? "파일 용량은 20MB 이하만 업로드할 수 있습니다." : "업로드에 실패했습니다.";
      return res.status(400).json({ error: message });
    }
    const user = await getSessionUser(req);
    if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
    try {
      const studentId = req.body.studentId;
      if (!studentId) return res.status(400).json({ error: "studentId가 필요합니다." });
      const access = await resolveStudentAccess(user, studentId);
      if (!access.canManage) return res.status(403).json({ error: "본인의 과제방에만 업로드할 수 있습니다." });

      const file = req.file;
      if (!file) return res.status(400).json({ error: "파일을 선택해주세요." });
      const ext = (file.originalname.match(/\.[^.]+$/) || [""])[0].toLowerCase();
      const mimeType = ALLOWED_MATERIAL_TYPES[ext];
      if (!mimeType) return res.status(400).json({ error: "md 또는 pdf 파일만 업로드할 수 있습니다." });

      const blob = await put(`assignments/${studentId}/${crypto.randomUUID()}${ext}`, file.buffer, {
        access: "public",
        contentType: mimeType
      });

      const assignment = await db.createAssignment({
        studentId,
        title: (req.body.title || file.originalname.replace(ext, "")).trim() || file.originalname,
        fileName: file.originalname,
        mimeType,
        sizeBytes: file.size,
        blobUrl: blob.url,
        blobPathname: blob.pathname,
        uploadedBy: user.id
      });
      res.status(201).json({ assignment });
    } catch (uploadErr) {
      console.error(uploadErr);
      res.status(500).json({ error: "서버 오류가 발생했습니다." });
    }
  });
});

app.patch("/api/assignments/:id", async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  try {
    const assignment = await db.getAssignmentById(req.params.id);
    if (!assignment) return res.status(404).json({ error: "찾을 수 없습니다." });
    const access = await resolveStudentAccess(user, assignment.student_id);
    if (!access.canManage) return res.status(403).json({ error: "본인의 과제만 수정할 수 있습니다." });
    const title = (req.body.title || "").trim();
    if (!title) return res.status(400).json({ error: "제목을 입력해주세요." });
    const updated = await db.renameAssignment(assignment.id, title);
    res.json({ assignment: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.delete("/api/assignments/:id", async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: "로그인이 필요합니다." });
  try {
    const assignment = await db.getAssignmentById(req.params.id);
    if (!assignment) return res.status(404).json({ error: "찾을 수 없습니다." });
    const access = await resolveStudentAccess(user, assignment.student_id);
    if (!access.canManage) return res.status(403).json({ error: "본인의 과제만 삭제할 수 있습니다." });
    await del(assignment.blob_pathname).catch(() => {});
    await db.deleteAssignment(assignment.id);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.get("/api/dashboard", requireAdmin, async (req, res) => {
  try {
    const data = await dashboard.getDashboard();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/requests/:id/approve", requireAdmin, async (req, res) => {
  try {
    const studentId = await dashboard.approveRequest(req.params.id);
    if (!studentId) return res.status(404).json({ error: "찾을 수 없습니다." });
    const data = await dashboard.getDashboard();
    res.json(Object.assign({ studentId }, data));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/students/:id/lessons", requireAdmin, async (req, res) => {
  try {
    const result = await dashboard.logLesson(req.params.id, req.body.note || "");
    if (!result) return res.status(404).json({ error: "찾을 수 없습니다." });
    const data = await dashboard.getDashboard();
    res.json(Object.assign({}, result, data));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/students/:id/invoices", requireAdmin, async (req, res) => {
  try {
    const ok = await dashboard.issueInvoice(req.params.id);
    if (!ok) return res.status(404).json({ error: "찾을 수 없습니다." });
    const data = await dashboard.getDashboard();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/invoices/:id/confirm", requireAdmin, async (req, res) => {
  try {
    const ok = await dashboard.confirmInvoicePayment(req.params.id);
    if (!ok) return res.status(404).json({ error: "찾을 수 없습니다." });
    const data = await dashboard.getDashboard();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

const COMMENT_NAME_MAX = 30;
const COMMENT_CONTENT_MAX = 500;

app.get("/api/comments", async (req, res) => {
  const page = (req.query.page || "").trim();
  if (!page) return res.status(400).json({ error: "page 파라미터가 필요합니다." });
  try {
    const comments = await db.listComments(page);
    res.json({ comments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/comments", async (req, res) => {
  try {
    const { page, name, content } = req.body || {};
    const p = (page || "").trim();
    const n = (name || "").trim();
    const c = (content || "").trim();
    if (!p) return res.status(400).json({ error: "page가 필요합니다." });
    if (!n) return res.status(400).json({ error: "이름을 입력해주세요." });
    if (!c) return res.status(400).json({ error: "댓글 내용을 입력해주세요." });
    if (n.length > COMMENT_NAME_MAX) return res.status(400).json({ error: `이름은 ${COMMENT_NAME_MAX}자 이내로 입력해주세요.` });
    if (c.length > COMMENT_CONTENT_MAX) return res.status(400).json({ error: `댓글은 ${COMMENT_CONTENT_MAX}자 이내로 입력해주세요.` });
    const comment = await db.createComment({ page: p, name: n, content: c });
    res.status(201).json({ comment });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

// ── 잠금 강의(ai.html / aiu.html) 서버측 인증 ──────────────────────────────
// 콘텐츠(content_html)와 비밀번호 해시는 DB(lesson_pages)에만 저장되며,
// 올바른 비밀번호를 서버가 확인한 뒤에만 /api/lesson-content가 본문을 내려준다.
// 정적 파일(ai.html/aiu.html)에는 잠금화면 UI만 남고 실제 본문은 포함되지 않는다.
const LESSON_PAGES = ["ai", "aiu", "ais"];
const LESSON_TTL_MS = 180 * 24 * 60 * 60 * 1000; // 180일

function lessonCookieName(page) {
  return `lesson_${page}`;
}

app.post("/api/lesson-auth", async (req, res) => {
  try {
    const { page, password } = req.body || {};
    const p = (page || "").trim();
    if (!LESSON_PAGES.includes(p)) return res.status(400).json({ error: "잘못된 페이지입니다." });
    if (typeof password !== "string" || !password) {
      return res.status(400).json({ error: "비밀번호를 입력해주세요." });
    }
    const lesson = await db.getLessonPage(p);
    if (!lesson || !bcrypt.compareSync(password, lesson.password_hash)) {
      return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });
    }
    const token = jwt.sign({ page: p }, JWT_SECRET, { expiresIn: "180d" });
    res.cookie(lessonCookieName(p), token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: LESSON_TTL_MS
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.get("/api/lesson-content", async (req, res) => {
  try {
    const p = (req.query.page || "").trim();
    if (!LESSON_PAGES.includes(p)) return res.status(400).json({ error: "잘못된 페이지입니다." });
    const token = req.cookies[lessonCookieName(p)];
    if (!token) return res.status(401).json({ error: "인증이 필요합니다." });
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "인증이 만료되었거나 올바르지 않습니다." });
    }
    if (payload.page !== p) return res.status(401).json({ error: "인증이 올바르지 않습니다." });
    const lesson = await db.getLessonPage(p);
    if (!lesson) return res.status(404).json({ error: "콘텐츠를 찾을 수 없습니다." });
    res.json({ html: lesson.content_html });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

// 관리자 전용: 잠금 강의 본문/비밀번호 등록 및 교체 (justice11419@naver.com 로그인 세션 필요)
app.post("/api/admin/lesson-content", requireAdmin, async (req, res) => {
  try {
    const { page, password, html } = req.body || {};
    const p = (page || "").trim();
    if (!LESSON_PAGES.includes(p)) return res.status(400).json({ error: "잘못된 페이지입니다." });
    if (typeof html !== "string" || !html.trim()) {
      return res.status(400).json({ error: "콘텐츠(html)가 필요합니다." });
    }
    let passwordHash;
    if (typeof password === "string" && password) {
      passwordHash = bcrypt.hashSync(password, 10);
    } else {
      const existingLesson = await db.getLessonPage(p);
      if (!existingLesson) {
        return res.status(400).json({ error: "최초 등록 시 password가 필요합니다." });
      }
      passwordHash = existingLesson.password_hash;
    }
    const result = await db.upsertLessonPage({ page: p, passwordHash, contentHtml: html });
    res.json({ ok: true, page: result.page, updatedAt: result.updated_at });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

const KRDICT_API_KEY = process.env.KRDICT_API_KEY;
const STDICT_API_KEY = process.env.STDICT_API_KEY;

app.get("/api/dictionary/krdict", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.status(400).json({ error: "검색어를 입력해주세요." });
  if (!KRDICT_API_KEY) return res.status(503).json({ error: "사전 서비스가 아직 설정되지 않았습니다." });
  try {
    const url = "https://krdict.korean.go.kr/api/search?" + new URLSearchParams({ key: KRDICT_API_KEY, q, num: "10" });
    const apiRes = await fetch(url);
    const xml = await apiRes.text();
    if (/<error_code>/.test(xml)) {
      const msg = (xml.match(/<message>([^<]*)<\/message>/) || [])[1] || "사전 조회에 실패했습니다.";
      return res.status(502).json({ error: msg });
    }
    const items = [];
    const blocks = xml.match(/<item>[\s\S]*?<\/item>/g) || [];
    for (const block of blocks) {
      const word = (block.match(/<word>([^<]*)<\/word>/) || [])[1] || "";
      const grade = (block.match(/<word_grade>([^<]*)<\/word_grade>/) || [])[1] || "";
      const defs = [...block.matchAll(/<definition>([^<]*)<\/definition>/g)].map((m) => m[1]);
      items.push({ word, grade, definitions: defs });
    }
    res.json({ items });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

app.get("/api/dictionary/stdict", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.status(400).json({ error: "검색어를 입력해주세요." });
  if (!STDICT_API_KEY) return res.status(503).json({ error: "사전 서비스가 아직 설정되지 않았습니다." });
  try {
    const url = "https://stdict.korean.go.kr/api/search.do?" + new URLSearchParams({ key: STDICT_API_KEY, q, req_type: "json", num: "10" });
    const apiRes = await fetch(url);
    const data = await apiRes.json();
    if (data.error) return res.status(502).json({ error: data.error.message || "사전 조회에 실패했습니다." });
    const rawItems = data.channel && data.channel.item ? (Array.isArray(data.channel.item) ? data.channel.item : [data.channel.item]) : [];
    const items = rawItems.map((it) => ({ word: it.word, definition: it.sense ? it.sense.definition : "" }));
    res.json({ items });
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
