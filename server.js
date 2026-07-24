import "dotenv/config";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();

// Railway terminates HTTPS one proxy hop before the application.
app.set("trust proxy", 1);
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const OTP_PEPPER = process.env.OTP_PEPPER || "";

const NODE_ENV = String(process.env.NODE_ENV || "production")
  .trim()
  .toLowerCase();
const SMS_DEV_MODE_REQUESTED =
  String(process.env.SMS_DEV_MODE || "false").trim().toLowerCase() === "true";
const ALLOW_DEV_OTP_RESPONSE =
  String(process.env.ALLOW_DEV_OTP_RESPONSE || "false")
    .trim()
    .toLowerCase() === "true";
const SMS_DEV_MODE =
  NODE_ENV === "development" &&
  SMS_DEV_MODE_REQUESTED &&
  ALLOW_DEV_OTP_RESPONSE;
const ALIGO_TEST_MODE =
  String(process.env.ALIGO_TEST_MODE || "false") === "true";

const ALIGO_API_KEY = process.env.ALIGO_API_KEY || "";
const ALIGO_USER_ID = process.env.ALIGO_USER_ID || "";
const ALIGO_SENDER = process.env.ALIGO_SENDER || "";

const OTP_EXPIRE_MS = 5 * 60 * 1000;
const COOLDOWN_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;
const MAX_SENDS_PER_DAY = 10;
const IP_MINUTE_WINDOW_MS = 60 * 1000;
const IP_HOUR_WINDOW_MS = 60 * 60 * 1000;
const MAX_SEND_REQUESTS_PER_IP_MINUTE = 5;
const MAX_SEND_REQUESTS_PER_IP_HOUR = 30;
const ipSendRequestBuckets = new Map();

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !OTP_PEPPER) {
  console.error("[BOOT] Missing required env");
  process.exit(1);
}

if (SMS_DEV_MODE_REQUESTED && !SMS_DEV_MODE) {
  console.warn(
    "[BOOT] SMS dev mode request ignored outside explicitly allowed development mode",
  );
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

function normalizePhone(input) {
  return String(input || "")
    .trim()
    .replace(/\s+/g, "")
    .replace(/[^0-9+]/g, "");
}

function normalizeKoreanMobile(input) {
  let v = normalizePhone(input);

  if (v.startsWith("+82")) v = "0" + v.slice(3);
  else if (v.startsWith("82")) v = "0" + v.slice(2);

  const digits = v.replace(/[^0-9]/g, "");
  if (!/^010\d{8}$/.test(digits)) {
    return {
      ok: false,
      phone: "",
      reason: "전화번호는 010으로 시작하는 11자리 숫자여야 합니다.",
    };
  }

  return { ok: true, phone: digits };
}

function genOtp6() {
  return String(crypto.randomInt(100000, 1000000));
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function safeErrorCode(error) {
  if (!error || typeof error !== "object") return "unknown";
  return typeof error.code === "string" && error.code
    ? error.code
    : "unknown";
}

function isSameLocalDay(a, b) {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

function bad(res, status, message, extra = {}) {
  return res.status(status).json({
    error: message,
    ...extra,
  });
}

function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || "unknown")
    .trim()
    .replace(/^::ffff:/, "");
}

function checkAndRecordIpSendRequest(ip, nowMs = Date.now()) {
  const current = ipSendRequestBuckets.get(ip) || {
    minuteStartedAt: nowMs,
    minuteCount: 0,
    hourStartedAt: nowMs,
    hourCount: 0,
  };

  if (nowMs - current.minuteStartedAt >= IP_MINUTE_WINDOW_MS) {
    current.minuteStartedAt = nowMs;
    current.minuteCount = 0;
  }

  if (nowMs - current.hourStartedAt >= IP_HOUR_WINDOW_MS) {
    current.hourStartedAt = nowMs;
    current.hourCount = 0;
  }

  const minuteBlocked =
    current.minuteCount >= MAX_SEND_REQUESTS_PER_IP_MINUTE;
  const hourBlocked = current.hourCount >= MAX_SEND_REQUESTS_PER_IP_HOUR;

  if (minuteBlocked || hourBlocked) {
    const retryAfterMs = hourBlocked
      ? IP_HOUR_WINDOW_MS - (nowMs - current.hourStartedAt)
      : IP_MINUTE_WINDOW_MS - (nowMs - current.minuteStartedAt);

    ipSendRequestBuckets.set(ip, current);
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMs / 1000)),
    };
  }

  current.minuteCount += 1;
  current.hourCount += 1;
  ipSendRequestBuckets.set(ip, current);

  return { allowed: true, retryAfterSeconds: 0 };
}

function limitOtpSendRequestsByIp(req, res, next) {
  const result = checkAndRecordIpSendRequest(getClientIp(req));

  if (!result.allowed) {
    res.set("Retry-After", String(result.retryAfterSeconds));
    return bad(res, 429, "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.", {
      retry_after_seconds: result.retryAfterSeconds,
    });
  }

  return next();
}

const ipBucketCleanupTimer = setInterval(() => {
  const cutoff = Date.now() - IP_HOUR_WINDOW_MS;

  for (const [ip, bucket] of ipSendRequestBuckets.entries()) {
    if (bucket.hourStartedAt < cutoff) {
      ipSendRequestBuckets.delete(ip);
    }
  }
}, IP_HOUR_WINDOW_MS);
ipBucketCleanupTimer.unref();

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    sms_dev_mode: SMS_DEV_MODE,
    aligo_test_mode: ALIGO_TEST_MODE,
  });
});

app.post("/send-phone-otp", limitOtpSendRequestsByIp, async (req, res) => {
  try {
    const phoneRaw = typeof req.body?.phone === "string" ? req.body.phone : "";
    const kr = normalizeKoreanMobile(phoneRaw);

    if (!kr.ok) {
      return bad(res, 400, kr.reason);
    }

    const normalized = kr.phone;

    // 이미 인증된 번호는 차단
    const { data: dup, error: dupErr } = await supabase
      .from("profiles")
      .select("id")
      .eq("phone_number", normalized)
      .eq("phone_verified", true)
      .limit(1)
      .maybeSingle();

    if (dupErr) throw dupErr;

    if (dup?.id) {
      return bad(res, 409, "이미 사용된 전화번호입니다.", {
        code: "PHONE_ALREADY_VERIFIED",
      });
    }

    const { data: existing, error: existingErr } = await supabase
      .from("phone_verifications")
      .select("last_sent_at, send_count")
      .eq("phone_e164", normalized)
      .maybeSingle();

    if (existingErr) throw existingErr;

    const now = new Date();

    if (existing?.last_sent_at) {
      const lastSentAt = new Date(existing.last_sent_at);
      const diff = now.getTime() - lastSentAt.getTime();

      if (diff < COOLDOWN_MS) {
        return bad(
          res,
          429,
          `잠시 후 다시 시도해 주세요. (${Math.ceil(
            (COOLDOWN_MS - diff) / 1000,
          )}초 남음)`,
          {
            cooldown_seconds: Math.ceil((COOLDOWN_MS - diff) / 1000),
          },
        );
      }
    }

    const lastSentDate = existing?.last_sent_at
      ? new Date(existing.last_sent_at)
      : null;

    const nextSendCount =
      lastSentDate && isSameLocalDay(lastSentDate, now)
        ? Number(existing?.send_count ?? 0) + 1
        : 1;

    if (nextSendCount > MAX_SENDS_PER_DAY) {
      return bad(res, 429, "오늘 인증 요청 횟수를 초과했습니다.");
    }

    const otp = genOtp6();
    const codeHash = sha256Hex(`${normalized}:${otp}:${OTP_PEPPER}`);
    const expiresAt = new Date(Date.now() + OTP_EXPIRE_MS).toISOString();

    const { error: upsertErr } = await supabase
      .from("phone_verifications")
      .upsert(
        {
          phone_e164: normalized,
          code_hash: codeHash,
          expires_at: expiresAt,
          attempt_count: 0,
          send_count: nextSendCount,
          last_sent_at: now.toISOString(),
          verified_at: null,
        },
        { onConflict: "phone_e164" },
      );

    if (upsertErr) throw upsertErr;

    if (SMS_DEV_MODE) {
      console.log("[DEV] SMS skipped");

      return res.status(200).json({
        success: true,
        cooldown_seconds: Math.ceil(COOLDOWN_MS / 1000),
        dev_mode: true,
        dev_otp: otp,
      });
    }

    if (!ALIGO_API_KEY || !ALIGO_USER_ID || !ALIGO_SENDER) {
      return bad(res, 500, "SMS 발송 환경설정이 누락되었습니다.");
    }

    const formData = new URLSearchParams();
    formData.append("key", ALIGO_API_KEY);
    formData.append("user_id", ALIGO_USER_ID);
    formData.append("sender", ALIGO_SENDER);
    formData.append("receiver", normalized);
    formData.append("msg", `[수리야] 인증번호는 ${otp} 입니다.`);
    if (ALIGO_TEST_MODE) {
      formData.append("testmode_yn", "Y");
    }

    const aligoRes = await fetch("https://apis.aligo.in/send/", {
      method: "POST",
      body: formData,
    });

    const text = await aligoRes.text();
    let payload = {};
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { raw: text };
    }

    const resultCode = String(payload?.result_code ?? "");
    const success =
      aligoRes.ok &&
      (resultCode === "1" ||
        resultCode === "success" ||
        payload?.success === true);

    if (!success) {
      console.error("[ALIGO] send failed", {
        httpStatus: aligoRes.status,
        resultCode: resultCode || "unknown",
      });
      return bad(res, 502, "인증번호 전송에 실패했어요.");
    }

    return res.status(200).json({
      success: true,
      cooldown_seconds: Math.ceil(COOLDOWN_MS / 1000),
    });
  } catch (err) {
    console.error("[send-phone-otp] failed", {
      code: safeErrorCode(err),
    });
    return bad(res, 500, "서버 오류가 발생했어요.");
  }
});

app.post("/send-phone-reset-otp", limitOtpSendRequestsByIp, async (req, res) => {
  try {
    const phoneRaw = typeof req.body?.phone === "string" ? req.body.phone : "";
    const kr = normalizeKoreanMobile(phoneRaw);

    if (!kr.ok) {
      return bad(res, 400, kr.reason);
    }

    const normalized = kr.phone;

    // 재설정은 이미 인증된 번호만 가능
    const { data: owner, error: ownerErr } = await supabase
      .from("profiles")
      .select("id, phone_verified")
      .eq("phone_number", normalized)
      .eq("phone_verified", true)
      .maybeSingle();

    if (ownerErr) throw ownerErr;

    if (!owner?.id) {
      return bad(res, 404, "가입된 전화번호를 찾을 수 없습니다.", {
        code: "PHONE_NOT_FOUND",
      });
    }

    const { data: existing, error: existingErr } = await supabase
      .from("phone_reset_verifications")
      .select("last_sent_at, send_count")
      .eq("phone_e164", normalized)
      .maybeSingle();

    if (existingErr) throw existingErr;

    const now = new Date();

    if (existing?.last_sent_at) {
      const lastSentAt = new Date(existing.last_sent_at);
      const diff = now.getTime() - lastSentAt.getTime();

      if (diff < COOLDOWN_MS) {
        return bad(res, 429, "잠시 후 다시 시도해 주세요.", {
          cooldown_seconds: Math.ceil((COOLDOWN_MS - diff) / 1000),
        });
      }
    }

    const lastSentDate = existing?.last_sent_at
      ? new Date(existing.last_sent_at)
      : null;

    const nextSendCount =
      lastSentDate && isSameLocalDay(lastSentDate, now)
        ? Number(existing?.send_count ?? 0) + 1
        : 1;

    if (nextSendCount > MAX_SENDS_PER_DAY) {
      return bad(res, 429, "오늘 인증 요청 횟수를 초과했습니다.");
    }

    const otp = genOtp6();
    const codeHash = sha256Hex(`${normalized}:${otp}:${OTP_PEPPER}`);
    const expiresAt = new Date(Date.now() + OTP_EXPIRE_MS).toISOString();

    const { error: upsertErr } = await supabase
      .from("phone_reset_verifications")
      .upsert(
        {
          phone_e164: normalized,
          code_hash: codeHash,
          expires_at: expiresAt,
          attempt_count: 0,
          send_count: nextSendCount,
          last_sent_at: now.toISOString(),
          verified_at: null,
        },
        { onConflict: "phone_e164" },
      );

    if (upsertErr) throw upsertErr;

    if (SMS_DEV_MODE) {
      console.log("[DEV] Reset SMS skipped");
      return res.status(200).json({
        success: true,
        cooldown_seconds: Math.ceil(COOLDOWN_MS / 1000),
        dev_mode: true,
        dev_otp: otp,
      });
    }

    if (!ALIGO_API_KEY || !ALIGO_USER_ID || !ALIGO_SENDER) {
      return bad(res, 500, "SMS 발송 환경설정이 누락되었습니다.");
    }

    const formData = new URLSearchParams();
    formData.append("key", ALIGO_API_KEY);
    formData.append("user_id", ALIGO_USER_ID);
    formData.append("sender", ALIGO_SENDER);
    formData.append("receiver", normalized);
    formData.append("msg", `[수리야] 비밀번호 재설정 인증번호는 ${otp} 입니다.`);
    if (ALIGO_TEST_MODE) {
      formData.append("testmode_yn", "Y");
    }

    const aligoRes = await fetch("https://apis.aligo.in/send/", {
      method: "POST",
      body: formData,
    });

    const text = await aligoRes.text();
    let payload = {};
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { raw: text };
    }

    const resultCode = String(payload?.result_code ?? "");
    const success =
      aligoRes.ok &&
      (resultCode === "1" ||
        resultCode === "success" ||
        payload?.success === true);

    if (!success) {
      console.error("[ALIGO] reset send failed", {
        httpStatus: aligoRes.status,
        resultCode: resultCode || "unknown",
      });
      return bad(res, 502, "인증번호 전송에 실패했어요.");
    }

    return res.status(200).json({
      success: true,
      cooldown_seconds: Math.ceil(COOLDOWN_MS / 1000),
    });
  } catch (err) {
    console.error("[send-phone-reset-otp] failed", {
      code: safeErrorCode(err),
    });
    return bad(res, 500, "서버 오류가 발생했어요.");
  }
});
app.post("/verify-phone-otp", async (req, res) => {
  try {
    const phoneRaw = typeof req.body?.phone === "string" ? req.body.phone : "";
    const otpRaw = typeof req.body?.otp === "string" ? req.body.otp : "";

    const kr = normalizeKoreanMobile(phoneRaw);
    if (!kr.ok) {
      return bad(res, 400, kr.reason);
    }

    const phone = kr.phone;
    const otp = otpRaw.trim();

    if (!/^[0-9]{6}$/.test(otp)) {
      return bad(res, 400, "인증번호(6자리)를 입력해 주세요.");
    }

    const { data: dup, error: dupErr } = await supabase
      .from("profiles")
      .select("id")
      .eq("phone_number", phone)
      .eq("phone_verified", true)
      .limit(1)
      .maybeSingle();

    if (dupErr) throw dupErr;

    if (dup?.id) {
      return bad(res, 409, "이미 사용된 전화번호입니다.", {
        code: "PHONE_ALREADY_VERIFIED",
      });
    }

    const { data: row, error: rowErr } = await supabase
      .from("phone_verifications")
      .select("phone_e164, code_hash, expires_at, attempt_count")
      .eq("phone_e164", phone)
      .maybeSingle();

    if (rowErr) throw rowErr;

    if (!row) {
      return bad(res, 400, "인증 요청 기록이 없습니다. 다시 전송해 주세요.");
    }

    const attemptCount = Number(row.attempt_count ?? 0);
    if (attemptCount >= MAX_ATTEMPTS) {
      return bad(res, 429, "시도 횟수를 초과했습니다. 다시 전송해 주세요.");
    }

    const expiresAt = row.expires_at ? new Date(row.expires_at).getTime() : 0;
    if (!expiresAt || Date.now() > expiresAt) {
      return bad(res, 410, "인증번호가 만료되었습니다. 다시 전송해 주세요.");
    }

    let stored = "";
    if (row.phone_e164) {
      const s = normalizeKoreanMobile(row.phone_e164);
      if (s.ok) stored = s.phone;
    }

    if (stored && stored !== phone) {
      return bad(res, 400, "전송한 전화번호와 입력한 전화번호가 다릅니다.");
    }

    const expectHash = sha256Hex(`${phone}:${otp}:${OTP_PEPPER}`);
    const ok =
      typeof row.code_hash === "string" && row.code_hash === expectHash;

    if (!ok) {
      const nextAttempts = attemptCount + 1;

      await supabase
        .from("phone_verifications")
        .update({ attempt_count: nextAttempts })
        .eq("phone_e164", phone);

      return bad(res, 400, "인증번호가 올바르지 않습니다.", {
        attempts_left: Math.max(0, MAX_ATTEMPTS - nextAttempts),
      });
    }

    const now = new Date().toISOString();

    const { error: vErr } = await supabase
      .from("phone_verifications")
      .update({ verified_at: now, attempt_count: 0 })
      .eq("phone_e164", phone);

    if (vErr) throw vErr;

    return res.status(200).json({
      success: true,
      phone_verified: true,
    });
  } catch (err) {
    console.error("[verify-phone-otp] failed", {
      code: safeErrorCode(err),
    });
    return bad(res, 500, "서버 오류가 발생했어요.");
  }
});

app.listen(PORT, () => {
  console.log(`[BOOT] OTP server listening on :${PORT}`);
});
