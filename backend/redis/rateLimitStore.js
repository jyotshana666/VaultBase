'use strict';

const { getRedisClient } = require('./client');

// ── Failed Attempt Counters ───────────────────────────────────────────────────

const FAILURE_TTL_S = 15 * 60; // 15 minutes

/**
 * Record a failed authentication attempt for rate limiting.
 * Atomic increment with sliding TTL.
 */
async function recordFailure(email) {
  if (!email) return 0;
  const redis = getRedisClient();
  const key = `ratelimit:failed:${email.toLowerCase().trim()}`;
  const count = await redis.incr(key);
  // Set/refresh TTL on every increment so window slides
  await redis.expire(key, FAILURE_TTL_S);
  return count;
}

/**
 * Get the current failure count for an email.
 */
async function getFailureCount(email) {
  if (!email) return 0;
  const redis = getRedisClient();
  const key = `ratelimit:failed:${email.toLowerCase().trim()}`;
  const val = await redis.get(key);
  return val ? parseInt(val, 10) : 0;
}

/**
 * Reset failure counter on successful authentication.
 */
async function resetFailures(email) {
  if (!email) return;
  const redis = getRedisClient();
  const key = `ratelimit:failed:${email.toLowerCase().trim()}`;
  await redis.del(key);
}

// ── Registration Rate Limiting ───────────────────────────────────────────────

const REGISTER_TTL_S = 60 * 60; // 1 hour per IP
const REGISTER_MAX_PER_IP = process.env.NODE_ENV === 'test' ? 100 : 10;
// In test environment, allow up to 100 registrations per hour from same IP
// In production, limit to 10 per hour

/**
 * Record a registration attempt by IP address.
 * Returns { allowed: boolean, remaining: number }
 */
async function checkRegisterRateLimit(ip) {
  if (!ip) return { allowed: true, remaining: REGISTER_MAX_PER_IP };
  const redis = getRedisClient();
  const key = `ratelimit:register:${ip}`;
  
  // Use INCR and check count atomically
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, REGISTER_TTL_S);
  }
  
  const allowed = count <= REGISTER_MAX_PER_IP;
  return { 
    allowed, 
    remaining: Math.max(0, REGISTER_MAX_PER_IP - count) 
  };
}

/**
 * Get remaining registration attempts for an IP.
 */
async function getRegisterRemaining(ip) {
  if (!ip) return REGISTER_MAX_PER_IP;
  const result = await checkRegisterRateLimit(ip);
  return result.remaining;
}

// ── OTP Resend Rate Limiting (per MFA session) ───────────────────────────────

const OTP_RESEND_TTL_S = 60 * 60; // 1 hour per MFA session
const OTP_RESEND_MAX = 5; // Max OTP resends per MFA session per hour

/**
 * Check OTP resend rate limit for an MFA session.
 * Returns { allowed: boolean, remaining: number }
 */
async function checkOtpResendRateLimit(mfaToken) {
  if (!mfaToken) return { allowed: true, remaining: OTP_RESEND_MAX };
  const redis = getRedisClient();
  const key = `ratelimit:otp_resend:${mfaToken}`;
  
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, OTP_RESEND_TTL_S);
  }
  
  const allowed = count <= OTP_RESEND_MAX;
  return { 
    allowed, 
    remaining: Math.max(0, OTP_RESEND_MAX - count) 
  };
}

/**
 * Get remaining OTP resends for an MFA session.
 */
async function getOtpResendRemaining(mfaToken) {
  if (!mfaToken) return OTP_RESEND_MAX;
  const result = await checkOtpResendRateLimit(mfaToken);
  return result.remaining;
}

// ── Device Operations Rate Limiting ─────────────────────────────────────────

const DEVICE_OP_TTL_S = 60 * 60; // 1 hour per user
const DEVICE_OP_MAX = 20; // Max device operations per user per hour

/**
 * Check rate limit for device operations (register, revoke).
 * Returns { allowed: boolean, remaining: number }
 */
async function checkDeviceOpRateLimit(email) {
  if (!email) return { allowed: true, remaining: DEVICE_OP_MAX };
  const redis = getRedisClient();
  const key = `ratelimit:device_op:${email.toLowerCase().trim()}`;
  
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, DEVICE_OP_TTL_S);
  }
  
  const allowed = count <= DEVICE_OP_MAX;
  return { 
    allowed, 
    remaining: Math.max(0, DEVICE_OP_MAX - count) 
  };
}

/**
 * Get remaining device operations for a user.
 */
async function getDeviceOpRemaining(email) {
  if (!email) return DEVICE_OP_MAX;
  const result = await checkDeviceOpRateLimit(email);
  return result.remaining;
}

// ── WebAuthn Rate Limiting (registration/authentication attempts) ───────────

const WEBAUTHN_TTL_S = 60 * 60; // 1 hour per user
const WEBAUTHN_MAX = 10; // Max WebAuthn operations per user per hour

/**
 * Check rate limit for WebAuthn operations.
 * Returns { allowed: boolean, remaining: number }
 */
async function checkWebAuthnRateLimit(email) {
  if (!email) return { allowed: true, remaining: WEBAUTHN_MAX };
  const redis = getRedisClient();
  const key = `ratelimit:webauthn:${email.toLowerCase().trim()}`;
  
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, WEBAUTHN_TTL_S);
  }
  
  const allowed = count <= WEBAUTHN_MAX;
  return { 
    allowed, 
    remaining: Math.max(0, WEBAUTHN_MAX - count) 
  };
}

/**
 * Get remaining WebAuthn operations for a user.
 */
async function getWebAuthnRemaining(email) {
  if (!email) return WEBAUTHN_MAX;
  const result = await checkWebAuthnRateLimit(email);
  return result.remaining;
}

// ── Global IP Rate Limiting (brute force protection) ─────────────────────────

const GLOBAL_IP_TTL_S = 60; // 1 minute windows
const GLOBAL_IP_MAX = 100; // Max requests per IP per minute (all endpoints)

/**
 * Check global rate limit per IP (catch-all for brute force).
 * Returns { allowed: boolean, remaining: number }
 */
async function checkGlobalIpRateLimit(ip) {
  if (!ip) return { allowed: true, remaining: GLOBAL_IP_MAX };
  const redis = getRedisClient();
  const key = `ratelimit:global_ip:${ip}`;
  
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, GLOBAL_IP_TTL_S);
  }
  
  const allowed = count <= GLOBAL_IP_MAX;
  return { 
    allowed, 
    remaining: Math.max(0, GLOBAL_IP_MAX - count) 
  };
}

// ── Session Hijack History ────────────────────────────────────────────────────

const HIJACK_TTL_S = 60 * 60; // 1 hour

/**
 * Record a session hijack event for the risk engine.
 */
async function recordSessionHijack(email) {
  if (!email) return;
  const redis = getRedisClient();
  const emailLower = email.toLowerCase().trim();
  const key = `security:hijack:${emailLower}`;
  const count = await redis.incr(key);
  await redis.expire(key, HIJACK_TTL_S);
  return count;
}

/**
 * Get recent hijack event count for an email.
 * Returns { count, exists } where exists indicates if the key is live.
 */
async function getHijackHistory(email) {
  if (!email) return { count: 0, exists: false };
  const redis = getRedisClient();
  const emailLower = email.toLowerCase().trim();
  const key = `security:hijack:${emailLower}`;
  const val = await redis.get(key);
  if (val === null) return { count: 0, exists: false };
  return { count: parseInt(val, 10), exists: true };
}

// ── Last Login IP ─────────────────────────────────────────────────────────────

/**
 * Store the last login IP for an email.
 * No TTL — persistent for the life of the Redis instance.
 * On restart, the IP change signal is reset (safe — false negative is acceptable).
 */
async function setLastLoginIP(email, ip) {
  if (!email || !ip) return;
  const redis = getRedisClient();
  const key = `auth:lastip:${email.toLowerCase().trim()}`;
  await redis.set(key, ip);
}

/**
 * Get the last login IP for an email.
 */
async function getLastLoginIP(email) {
  if (!email) return null;
  const redis = getRedisClient();
  const key = `auth:lastip:${email.toLowerCase().trim()}`;
  return await redis.get(key);
}

module.exports = {
  // Failure tracking
  recordFailure,
  getFailureCount,
  resetFailures,
  // Registration rate limiting
  checkRegisterRateLimit,
  getRegisterRemaining,
  // OTP resend rate limiting
  checkOtpResendRateLimit,
  getOtpResendRemaining,
  // Device operations rate limiting
  checkDeviceOpRateLimit,
  getDeviceOpRemaining,
  // WebAuthn rate limiting
  checkWebAuthnRateLimit,
  getWebAuthnRemaining,
  // Global IP rate limiting
  checkGlobalIpRateLimit,
  // Hijack tracking
  recordSessionHijack,
  getHijackHistory,
  // IP tracking
  setLastLoginIP,
  getLastLoginIP,
};
