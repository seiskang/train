"use strict";

const db = require("./db");
const query = db.query;

const RATE = 20;
const PACK = 8;

let dashboardReady = null;

function ensureDashboardSchema() {
  if (!dashboardReady) {
    dashboardReady = (async () => {
      await db.ensureSchema();
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS initials TEXT");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS level TEXT");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS location TEXT");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS tz_offset TEXT");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS goal TEXT");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS slot TEXT");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS local_time TEXT");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS pay_status TEXT DEFAULT 'pending'");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS used_sessions INTEGER DEFAULT 0");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS total_sessions INTEGER DEFAULT 8");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS pay_method TEXT");
      await query("ALTER TABLE students ADD COLUMN IF NOT EXISTS profile_fields JSONB NOT NULL DEFAULT '[]'");

      await query(`
        CREATE TABLE IF NOT EXISTS lessons (
          id SERIAL PRIMARY KEY,
          student_id TEXT NOT NULL REFERENCES students(id),
          lesson_no INTEGER NOT NULL,
          lesson_date TEXT,
          topic TEXT,
          attend TEXT,
          tone TEXT,
          pron TEXT,
          vocab TEXT,
          hw TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      await query(`
        CREATE TABLE IF NOT EXISTS invoices (
          id SERIAL PRIMARY KEY,
          student_id TEXT NOT NULL REFERENCES students(id),
          period TEXT,
          sessions INTEGER,
          amount INTEGER,
          status TEXT NOT NULL DEFAULT 'pending',
          method TEXT,
          issued TEXT,
          kind TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      await query(`
        CREATE TABLE IF NOT EXISTS requests (
          id SERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          region TEXT,
          tz_offset TEXT,
          state TEXT,
          tone TEXT,
          level TEXT,
          wish TEXT,
          via TEXT,
          lang TEXT,
          note TEXT,
          slot TEXT,
          local_label TEXT,
          initials TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);

      await seedDashboardData();
    })();
  }
  return dashboardReady;
}

async function seedDashboardData() {
  const existing = await query("SELECT id FROM students WHERE id IN ('s1', 's2')");
  if (existing.rows.length === 0) return; // students 시드가 아직 안 됐으면(db.js에서 처리) 다음 요청에서 재시도

  await query(
    `UPDATE students SET
      initials = 'EC', level = '중급 1', location = '미국 시애틀', tz_offset = 'KST -16h',
      goal = '업무 이메일·회의 한국어', slot = '화·목 07:00', local_time = '월·수 15:00 PDT',
      pay_status = 'paid', used_sessions = 1, total_sessions = 8, pay_method = 'Wise',
      profile_fields = $1::jsonb
     WHERE id = 's1' AND level IS NULL`,
    [JSON.stringify([
      ["거주지 / 시차", "미국 시애틀 · KST -16h"],
      ["고정 슬롯", "화·목 07:00 KST (현지 월·수 15:00)"],
      ["학습 목표", "사내 회의·이메일에서 쓰는 존댓말"],
      ["모국어 / 가능 언어", "영어 · 한국어 중급 1"],
      ["결제 수단", "Wise · 월 8회 선불"],
      ["시작일", "2026년 4월 6일"]
    ])]
  );
  await query(
    `UPDATE students SET
      initials = 'NM', level = '초급 2', location = '한국 안산 (거주)', tz_offset = 'KST 동일',
      goal = '직장 대화 · TOPIK 2급', slot = '월·수 20:00', local_time = '동일 시간대',
      pay_status = 'paid', used_sessions = 1, total_sessions = 8, pay_method = '카카오페이',
      profile_fields = $1::jsonb
     WHERE id = 's2' AND level IS NULL`,
    [JSON.stringify([
      ["거주지 / 시차", "한국 안산 · KST 동일"],
      ["고정 슬롯", "월·수 20:00 KST"],
      ["학습 목표", "직장 동료와의 일상 대화, TOPIK 2급"],
      ["모국어 / 가능 언어", "베트남어 · 한국어 초급 2"],
      ["결제 수단", "카카오페이 · 월 8회 선불"],
      ["시작일", "2026년 6월 15일"]
    ])]
  );

  const lessonExisting = await query("SELECT id FROM lessons LIMIT 1");
  if (lessonExisting.rows.length === 0) {
    await query(
      `INSERT INTO lessons (student_id, lesson_no, lesson_date, topic, attend, tone, pron, vocab, hw)
       VALUES ('s1', 1, '8월 20일 (목)', '회의 진행 표현', '출석', 'success', '했습니다 받침 탈락 교정, 억양 하강 연습', '안건, 검토하다, 공유드리다 외 9개', '회의 요약 음성 3분 녹음')`
    );
    await query(
      `INSERT INTO lessons (student_id, lesson_no, lesson_date, topic, attend, tone, pron, vocab, hw)
       VALUES ('s2', 1, '8월 24일 (월)', '직장 인사·부탁 표현', '출석', 'success', '종성 ㅂ/ㅍ 구분', '부탁드려요, 도와주세요 외 8개', '동료와 실제 대화 3문장 녹음')`
    );
  }

  const invoiceExisting = await query("SELECT id FROM invoices LIMIT 1");
  if (invoiceExisting.rows.length === 0) {
    await query(
      `INSERT INTO invoices (student_id, period, sessions, amount, status, method, issued, kind)
       VALUES ('s1', '2026-08', 8, 160, 'paid', 'Wise', '8/01 발행', '정규 8회 패키지')`
    );
    await query(
      `INSERT INTO invoices (student_id, period, sessions, amount, status, method, issued, kind)
       VALUES ('s2', '2026-08', 8, 160, 'paid', '카카오페이', '8/12 발행', '정규 8회 패키지')`
    );
  }

  const requestExisting = await query("SELECT id FROM requests LIMIT 1");
  if (requestExisting.rows.length === 0) {
    await query(
      `INSERT INTO requests (name, region, tz_offset, state, tone, level, wish, via, lang, note, slot, local_label, initials)
       VALUES ('Lucas Silva', '브라질 상파울루', 'KST -12h', '신규', 'brand', '초급 1 희망', '화·목 22:00 KST (현지 10:00)', '인스타그램 DM', '포르투갈어 · 영어',
       '한국 회사 취업 준비 중입니다. 한글은 읽을 수 있고 말하기 연습이 필요합니다. 주 2회 8회 패키지로 시작하고 싶습니다.', '화·목 22:00', '현지 화·목 10:00', 'LS')`
    );
    await query(
      `INSERT INTO requests (name, region, tz_offset, state, tone, level, wish, via, lang, note, slot, local_label, initials)
       VALUES ('Chen Wei', '대만 타이베이', 'KST -1h', '상담 완료', 'info', '중급 1 희망', '토·일 11:00 KST (현지 10:00)', '기존 학생 소개', '중국어 · 영어',
       'TOPIK 3급 목표입니다. 발음 교정 중심으로 진행하고 싶고, 첫 달은 8회 기본 패키지로 시작하겠습니다.', '토·일 11:00', '현지 토·일 10:00', 'CW')`
    );
  }
}

function toStudentDto(row, lessonsByStudent) {
  return {
    id: row.id,
    name: row.name,
    initials: row.initials,
    level: row.level,
    where: row.location,
    offset: row.tz_offset,
    goal: row.goal,
    slot: row.slot,
    local: row.local_time,
    pay: row.pay_status,
    used: row.used_sessions,
    total: row.total_sessions,
    method: row.pay_method,
    fields: row.profile_fields || [],
    lessons: (lessonsByStudent[row.id] || []).map(toLessonDto)
  };
}

function toLessonDto(row) {
  return {
    no: row.lesson_no,
    date: row.lesson_date,
    topic: row.topic,
    attend: row.attend,
    tone: row.tone,
    pron: row.pron,
    vocab: row.vocab,
    hw: row.hw
  };
}

function toInvoiceDto(row) {
  return {
    id: row.id,
    sid: row.student_id,
    period: row.period,
    sessions: row.sessions,
    amount: row.amount,
    status: row.status,
    method: row.method,
    issued: row.issued,
    kind: row.kind
  };
}

function toRequestDto(row) {
  return {
    id: row.id,
    name: row.name,
    region: row.region,
    offset: row.tz_offset,
    state: row.state,
    tone: row.tone,
    level: row.level,
    wish: row.wish,
    via: row.via,
    lang: row.lang,
    note: row.note,
    slot: row.slot,
    localLabel: row.local_label,
    initials: row.initials
  };
}

async function getDashboard() {
  await ensureDashboardSchema();
  const [studentsRes, lessonsRes, invoicesRes, requestsRes] = await Promise.all([
    query("SELECT * FROM students WHERE level IS NOT NULL ORDER BY id"),
    query("SELECT * FROM lessons ORDER BY lesson_no DESC"),
    query("SELECT * FROM invoices ORDER BY created_at DESC"),
    query("SELECT * FROM requests ORDER BY created_at ASC")
  ]);
  const lessonsByStudent = {};
  for (const row of lessonsRes.rows) {
    (lessonsByStudent[row.student_id] = lessonsByStudent[row.student_id] || []).push(row);
  }
  return {
    students: studentsRes.rows.map((row) => toStudentDto(row, lessonsByStudent)),
    invoices: invoicesRes.rows.map(toInvoiceDto),
    requests: requestsRes.rows.map(toRequestDto)
  };
}

async function approveRequest(requestId) {
  await ensureDashboardSchema();
  const { rows } = await query("SELECT * FROM requests WHERE id = $1", [requestId]);
  const r = rows[0];
  if (!r) return null;

  const studentId = "n" + r.id;
  await query(
    `INSERT INTO students (id, name, email, initials, level, location, tz_offset, goal, slot, local_time, pay_status, used_sessions, total_sessions, pay_method, profile_fields)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', 0, $11, 'PayPal', $12::jsonb)`,
    [
      studentId,
      r.name,
      `${studentId}@example.com`,
      r.initials,
      (r.level || "").replace(" 희망", ""),
      r.region,
      r.tz_offset,
      (r.note || "").slice(0, 22) + "…",
      r.slot,
      r.local_label,
      PACK,
      JSON.stringify([
        ["거주지 / 시차", `${r.region} · ${r.tz_offset}`],
        ["고정 슬롯", `${r.slot} KST (${r.local_label})`],
        ["학습 목표", `${r.level} · 상담 메모 참고`],
        ["모국어 / 가능 언어", r.lang],
        ["결제 수단", "PayPal · 월 8회 선불"],
        ["시작일", "첫 수업 예정"]
      ])
    ]
  );
  await query(
    `INSERT INTO invoices (student_id, period, sessions, amount, status, method, issued, kind)
     VALUES ($1, '2026-09', $2, $3, 'pending', 'PayPal', '자동 발행', '정규 8회 패키지 (자동)')`,
    [studentId, PACK, PACK * RATE]
  );
  await query("DELETE FROM requests WHERE id = $1", [requestId]);
  return studentId;
}

async function logLesson(studentId, note) {
  await ensureDashboardSchema();
  const { rows } = await query("SELECT * FROM students WHERE id = $1", [studentId]);
  const st = rows[0];
  if (!st) return null;

  const countRes = await query("SELECT COUNT(*)::int AS n FROM lessons WHERE student_id = $1", [studentId]);
  const lessonNo = countRes.rows[0].n + 1;
  const parts = (note || "").split(/[,·/]/).map((x) => x.trim()).filter(Boolean);
  const lessonDate = new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul", month: "long", day: "numeric", weekday: "short"
  }).format(new Date());
  await query(
    `INSERT INTO lessons (student_id, lesson_no, lesson_date, topic, attend, tone, pron, vocab, hw)
     VALUES ($1, $2, $7, $3, '출석', 'success', $4, $5, $6)`,
    [
      studentId,
      lessonNo,
      parts[0] || "자유 대화 50분",
      parts[1] || "이번 회차 발음 메모 없음",
      parts[2] || "이번 회차 어휘 메모 없음",
      parts[3] || "다음 수업 전 음성 과제 1건",
      lessonDate
    ]
  );
  const usedSessions = Math.min(st.total_sessions, lessonNo);
  await query("UPDATE students SET used_sessions = $1 WHERE id = $2", [usedSessions, studentId]);
  return { usedSessions, totalSessions: st.total_sessions };
}

async function issueInvoice(studentId) {
  await ensureDashboardSchema();
  const { rows } = await query("SELECT * FROM students WHERE id = $1", [studentId]);
  const st = rows[0];
  if (!st) return null;
  await query(
    `INSERT INTO invoices (student_id, period, sessions, amount, status, method, issued, kind)
     VALUES ($1, '2026-09', $2, $3, 'pending', $4, '방금 발행', '정규 8회 패키지')`,
    [studentId, PACK, PACK * RATE, st.pay_method || "PayPal"]
  );
  return true;
}

async function confirmInvoicePayment(invoiceId) {
  await ensureDashboardSchema();
  const { rows } = await query("SELECT * FROM invoices WHERE id = $1", [invoiceId]);
  const inv = rows[0];
  if (!inv) return null;
  await query("UPDATE invoices SET status = 'paid', issued = issued || ' · 입금 확인' WHERE id = $1", [invoiceId]);
  await query(
    "UPDATE students SET pay_status = 'paid', used_sessions = 0, total_sessions = $1 WHERE id = $2",
    [inv.sessions, inv.student_id]
  );
  return true;
}

module.exports = {
  ensureDashboardSchema,
  getDashboard,
  approveRequest,
  logLesson,
  issueInvoice,
  confirmInvoicePayment
};
