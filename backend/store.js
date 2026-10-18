"use strict";

/**
 * VaultBase — Persistence-Backed Store  (Phase 10)
 *
 * Single async persistence interface.
 * All methods are async. No parallel in-memory production paths.
 *
 * Durable state  → PostgreSQL  (users, devices, credentials, sessions, audit, risk, alerts)
 * Ephemeral state → Redis      (OTP challenges, WebAuthn challenges, MFA sessions,
 *                                revoked JTI cache, rate limits, hijack history)
 */

const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

// ── PostgreSQL repositories ──────────────────────────────────────────────────
const dbUsers = require("./db/users");
const dbDevices = require("./db/devices");
const dbCredentials = require("./db/credentials");
const dbSessions = require("./db/sessions");
const dbAuditLogs = require("./db/auditLogs");
const dbRiskEvents = require("./db/riskEvents");
const dbSecurityAlerts = require("./db/securityAlerts");

// ── Redis stores ──────────────────────────────────────────────────────────────
const otpStore = require("./redis/otpStore");
const webauthnStore = require("./redis/webauthnStore");
const mfaSessionStore = require("./redis/mfaSessionStore");
const sessionCache = require("./redis/sessionCache");
const rateLimitStore = require("./redis/rateLimitStore");

// ── In-memory event buffers (non-critical, ephemeral within process) ────────
// These are supplementary logs that enhance the Security Dashboard.
// They do NOT contain security-critical state and losing them on restart is acceptable.
// Durable audit trail is in PostgreSQL (audit_logs + risk_events tables).
const anomalyLogs = [];   // Array of { type, email, details, timestamp }
const sessionEvents = [];  // Structured session event log
const riskAuditLogs = [];  // Risk assessment audit trail (per-process, also persisted to DB)

// ── OTP Secret ────────────────────────────────────────────────────────────────
const OTP_SECRET = process.env.OTP_SECRET || "vaultbase-otp-secret-salt-key-dev";

// ── Seed demo users ───────────────────────────────────────────────────────────
async function seedUsers() {
  const demoUsers = [
    { email: "demo@vaultbase.io", password: "demo1234" },
    { email: "alice@example.com", password: "alice1234" },
    { email: "bob@example.com", password: "bob1234" },
    { email: "admin@vaultbase.io", password: "admin1234" },
  ];

  for (const u of demoUsers) {
    const existing = await dbUsers.findUserByEmail(u.email);
    if (existing) continue; // Already seeded

    const hash = await bcrypt.hash(u.password, 10);
    const id = uuidv4();
    await dbUsers.createUser({ id, email: u.email, passwordHash: hash });

    // Seed trusted device
    await dbDevices.registerDevice(u.email, "initial-demo-fingerprint", "Demo Primary Laptop", "127.0.0.1");
    await rateLimitStore.setLastLoginIP(u.email, "127.0.0.1");
  }
  console.log(`[Store] Seeded ${demoUsers.length} demo users with trusted devices`);
}

// ── User Operations (PostgreSQL) ──────────────────────────────────────────────

async function getUser(email) {
  return dbUsers.findUserByEmail(email);
}

async function getUserById(id) {
  return dbUsers.findUserById(id);
}

async function createUser({ id, email, passwordHash, faceDescriptor }) {
  return dbUsers.createUser({ id, email, passwordHash, faceDescriptor });
}

async function updateFaceDescriptor(userId, faceDescriptor) {
  return dbUsers.updateFaceDescriptor(userId, faceDescriptor);
}

async function listUsers() {
  return dbUsers.listUsers();
}

// ── Device Trust Lifecycle (PostgreSQL) ───────────────────────────────────────

async function getDevice(email, fingerprint) {
  return dbDevices.getDevice(email, fingerprint);
}

async function getDeviceStatus(email, fingerprint) {
  return dbDevices.getDeviceStatus(email, fingerprint);
}

async function getUserDevices(email) {
  return dbDevices.getUserDevices(email);
}

async function registerDevice(email, fingerprint, deviceName, ip) {
  return dbDevices.registerDevice(email, fingerprint, deviceName, ip);
}

async function revokeDevice(email, fingerprintOrId) {
  const result = await dbDevices.revokeDevice(email, fingerprintOrId);
  if (result) {
    await logAnomaly(email, "DEVICE_REVOKED", { fingerprint: fingerprintOrId });
  }
  return result;
}

// ── WebAuthn Credential Storage (PostgreSQL) ──────────────────────────────────

async function saveWebAuthnCredential(userId, credInfo) {
  return dbCredentials.saveCredential(userId, credInfo);
}

async function getWebAuthnCredential(userId, credentialId) {
  return dbCredentials.getCredential(userId, credentialId);
}

async function updateWebAuthnCredential(userId, credentialId, updates) {
  return dbCredentials.updateCredentialSignCount(userId, credentialId, updates);
}

async function getUserWebAuthnCredentials(userId) {
  return dbCredentials.getUserCredentials(userId);
}

// ── WebAuthn Challenge Store (Redis) ──────────────────────────────────────────

async function generateWebAuthnChallenge(mfaToken, userId, ceremony) {
  return webauthnStore.generateWebAuthnChallenge(mfaToken, userId, ceremony);
}

async function consumeWebAuthnChallenge(mfaToken, expectedUserId) {
  return webauthnStore.consumeWebAuthnChallenge(mfaToken, expectedUserId);
}

async function peekAndInvalidateWebAuthnChallenge(mfaToken, expectedUserId) {
  return webauthnStore.peekAndInvalidateWebAuthnChallenge(mfaToken, expectedUserId);
}

async function getWebAuthnChallenge(mfaToken) {
  return webauthnStore.getWebAuthnChallenge(mfaToken);
}

// ── MFA In-Flight Sessions (Redis) ────────────────────────────────────────────

async function createMfaSession(mfaToken, sessionData) {
  return mfaSessionStore.createMfaSession(mfaToken, sessionData);
}

async function getMfaSession(mfaToken) {
  return mfaSessionStore.getMfaSession(mfaToken);
}

async function updateMfaSession(mfaToken, updates) {
  return mfaSessionStore.updateMfaSession(mfaToken, updates);
}

async function deleteMfaSession(mfaToken) {
  return mfaSessionStore.deleteMfaSession(mfaToken);
}

// ── Issued Sessions (PostgreSQL authoritative + Redis cache) ──────────────────

async function createIssuedSession(jti, { userId, email, deviceFp, ip, userAgent, accessTtlMs }) {
  const session = await dbSessions.createSession({ jti, userId, email, deviceFp, ip, userAgent, accessTtlMs });
  
  // Cache in Redis for low-latency lookups
  const ttlSeconds = Math.ceil((accessTtlMs || 3600000) / 1000);
  await sessionCache.cacheActiveSession(jti, session, ttlSeconds);
  
  logSessionEvent("SESSION_CREATED", jti, userId, email, ip, {
    deviceFp,
    userAgent: (userAgent || "").slice(0, 256),
    expiresAt: session.expiresAt ? new Date(session.expiresAt).toISOString() : null,
  });
  
  return session;
}

async function getIssuedSession(jti) {
  if (!jti) return null;

  // Fast path: check Redis revoked cache first
  const revoked = await sessionCache.isJtiRevoked(jti);
  if (revoked) {
    return { jti, status: "revoked" };
  }

  // Try Redis active session cache
  let session = await sessionCache.getActiveSession(jti);
  if (session) {
    // Lazy expiry check
    if (session.status === "active" && Date.now() > session.expiresAt) {
      session.status = "expired";
      await sessionCache.removeActiveSession(jti);
    }
    return session;
  }

  // Fall through to PostgreSQL (authoritative)
  session = await dbSessions.getSessionByJti(jti);
  return session;
}

async function revokeSession(jti, reason = "admin") {
  if (!jti) return false;

  // Revoke in PostgreSQL (authoritative)
  const result = await dbSessions.revokeSession(jti, reason);

  // Mark revoked in Redis for distributed fast-path
  await sessionCache.cacheRevokedJti(jti, 3600);
  await sessionCache.removeActiveSession(jti);

  if (result) {
    const session = await dbSessions.getSessionByJti(jti);
    logSessionEvent("SESSION_REVOKED", jti, session?.userId, session?.email, session?.ip, { reason });
    console.log(`[Session] Revoked session ${jti.slice(0, 8)}… (reason: ${reason})`);
  }
  return result;
}

async function revokeAllSessions(userId, reason = "revoke-all") {
  // Get all active sessions first so we can cache revocations in Redis
  const userSessions = await dbSessions.getUserSessions(userId);
  const activeSessions = userSessions.filter(s => s.status === "active");

  const count = await dbSessions.revokeAllUserSessions(userId, reason);

  // Mark each in Redis revoked cache
  for (const s of activeSessions) {
    if (s.jti) {
      await sessionCache.cacheRevokedJti(s.jti, 3600);
      await sessionCache.removeActiveSession(s.jti);
    }
  }

  return count;
}

async function getUserSessions(userId) {
  return dbSessions.getUserSessions(userId);
}

async function recordSessionContextChange(jti, email, details) {
  const result = await dbSessions.recordContextChange(jti, details);
  logSessionEvent("SESSION_CONTEXT_CHANGE", jti, result?.userId, email, details?.currentIP, details);

  // Invalidate the Redis active session cache so the next read reflects the updated contextChanges
  await sessionCache.removeActiveSession(jti);

  return result;
}

async function touchSession(jti) {
  return dbSessions.touchSession(jti);
}

// ── Token Blacklist (Redis) ───────────────────────────────────────────────────
// The raw-token blacklist is maintained for backward compatibility.
// The primary revocation mechanism is the JTI-based revoked cache.

async function blacklistToken(tokenOrJti) {
  // Cache in Redis revoked JTI set
  return sessionCache.cacheRevokedJti(tokenOrJti, 3600);
}

async function isTokenBlacklisted(tokenOrJti) {
  return sessionCache.isJtiRevoked(tokenOrJti);
}

// ── Rate Limiting & Failure Tracking (Redis) ──────────────────────────────────

async function recordFailure(email) {
  return rateLimitStore.recordFailure(email);
}

async function getFailureCount(email) {
  return rateLimitStore.getFailureCount(email);
}

async function resetFailures(email) {
  return rateLimitStore.resetFailures(email);
}

// Registration rate limiting
async function checkRegisterRateLimit(ip) {
  return rateLimitStore.checkRegisterRateLimit(ip);
}

async function getRegisterRemaining(ip) {
  return rateLimitStore.getRegisterRemaining(ip);
}

// OTP resend rate limiting
async function checkOtpResendRateLimit(mfaToken) {
  return rateLimitStore.checkOtpResendRateLimit(mfaToken);
}

async function getOtpResendRemaining(mfaToken) {
  return rateLimitStore.getOtpResendRemaining(mfaToken);
}

// Device operations rate limiting
async function checkDeviceOpRateLimit(email) {
  return rateLimitStore.checkDeviceOpRateLimit(email);
}

async function getDeviceOpRemaining(email) {
  return rateLimitStore.getDeviceOpRemaining(email);
}

// WebAuthn rate limiting
async function checkWebAuthnRateLimit(email) {
  return rateLimitStore.checkWebAuthnRateLimit(email);
}

async function getWebAuthnRemaining(email) {
  return rateLimitStore.getWebAuthnRemaining(email);
}

// Global IP rate limiting
async function checkGlobalIpRateLimit(ip) {
  return rateLimitStore.checkGlobalIpRateLimit(ip);
}

async function updateLastLogin(email, ip) {
  return rateLimitStore.setLastLoginIP(email, ip);
}

async function recordSessionHijack(email) {
  return rateLimitStore.recordSessionHijack(email);
}

async function getHijackHistory(email) {
  return rateLimitStore.getHijackHistory(email);
}

// ── Audit & Risk Logging (PostgreSQL + in-memory buffer) ─────────────────────

async function logAuditEvent(eventData) {
  return dbAuditLogs.logAuditEvent(eventData);
}

async function getUserAuditLogs(emailOrUserId, limit) {
  return dbAuditLogs.getUserAuditLogs(emailOrUserId, limit);
}

async function logRiskEvent(eventData) {
  return dbRiskEvents.logRiskEvent(eventData);
}

async function getUserRiskEvents(emailOrUserId, limit) {
  return dbRiskEvents.getUserRiskEvents(emailOrUserId, limit);
}

async function createSecurityAlert(alertData) {
  return dbSecurityAlerts.createSecurityAlert(alertData);
}

async function getUserAlerts(userId, limit) {
  return dbSecurityAlerts.getUserAlerts(userId, limit);
}

async function markAlertRead(alertId, userId) {
  return dbSecurityAlerts.markAlertRead(alertId, userId);
}

// ── Anomaly Log (in-memory buffer + async DB persistence) ─────────────────────

async function logAnomaly(email, type, details) {
  const entry = { email, type, details, timestamp: new Date().toISOString() };
  anomalyLogs.push(entry);
  console.warn(`[ANOMALY] ${type} for ${email}:`, details);

  // Also persist to risk_events in PostgreSQL (fire-and-forget)
  try {
    await dbRiskEvents.logRiskEvent({
      email,
      eventType: type,
      details,
    });
  } catch (err) {
    console.error("[Store] Failed to persist anomaly to DB:", err.message);
  }
}

// ── IP Normalization ──────────────────────────────────────────────────────────
function normalizeIP(ip) {
  if (!ip) return "";
  const trimmed = ip.toString().trim();
  if (trimmed === "::1" || trimmed === "::ffff:127.0.0.1") return "127.0.0.1";
  return trimmed;
}

// ── Dynamic Factor Policy ─────────────────────────────────────────────────────
function getRequiredFactors(riskLevel) {
  switch (riskLevel) {
    case "LOW":
      return ["otp"];
    case "MEDIUM":
      return ["otp", "device"];
    case "HIGH":
      return ["otp", "face", "device"];
    case "CRITICAL":
      return ["otp", "face", "device", "webauthn"];
    default:
      return ["otp"];
  }
}

// ── Authoritative Risk Engine (async — reads Redis for failure/hijack state) ──
async function evaluateRisk(email, deviceFingerprint, currentIP, contextOverrides = {}) {
  let score = 0;
  const signals = [];
  const emailLower = (email || "").toLowerCase().trim();

  // 1. Device Trust Signal (NEW = +30, REVOKED = +40, TRUSTED = +0)
  const deviceStatus = await getDeviceStatus(emailLower, deviceFingerprint);
  if (deviceStatus === "REVOKED") {
    score += 40;
    signals.push({
      name: "REVOKED_DEVICE",
      weight: 40,
      description: "Authentication attempt from a previously revoked device",
    });
  } else if (deviceStatus === "NEW") {
    score += 30;
    signals.push({
      name: "NEW_DEVICE",
      weight: 30,
      description: `Unrecognized device fingerprint (${(deviceFingerprint || "none").slice(0, 12)}…)`,
    });
  }

  // 2. Unusual hour signal (before 6am / after 10pm): +15
  const currentHour = contextOverrides.hour !== undefined ? contextOverrides.hour : new Date().getHours();
  if (currentHour < 6 || currentHour >= 22) {
    score += 15;
    signals.push({
      name: "UNUSUAL_HOUR",
      weight: 15,
      description: `Authentication attempt during unusual hours (${currentHour}:00)`,
    });
  }

  // 3. Recent failed attempts (last 15 mins): +25
  const failureCount = contextOverrides.failedAttempts !== undefined
    ? contextOverrides.failedAttempts
    : await getFailureCount(emailLower);

  if (failureCount > 0) {
    score += 25;
    signals.push({
      name: "FAILED_ATTEMPTS",
      weight: 25,
      description: `${failureCount} recent failed authentication attempt(s)`,
    });
  }

  // 4. IP address changed from last login: +20
  const lastIP = normalizeIP(await rateLimitStore.getLastLoginIP(emailLower));
  const effectiveIP = normalizeIP(contextOverrides.ip || currentIP);
  if (lastIP && effectiveIP && lastIP !== effectiveIP) {
    score += 20;
    signals.push({
      name: "IP_CHANGE",
      weight: 20,
      description: `IP address changed from ${lastIP} to ${effectiveIP}`,
    });
  }

  // 5. Recent session hijack history: +35
  const hijackRec = await getHijackHistory(emailLower);
  if (hijackRec.exists && hijackRec.count > 0) {
    score += 35;
    signals.push({
      name: "SESSION_HIJACK_HISTORY",
      weight: 35,
      description: `${hijackRec.count} session hijack event(s) detected in the last hour`,
    });
  }

  // Cap normalized score at 100
  score = Math.min(100, Math.max(0, score));

  // Determine risk tier
  let level = "LOW";
  if (score > 80) level = "CRITICAL";
  else if (score > 60) level = "HIGH";
  else if (score > 30) level = "MEDIUM";

  const requiredFactors = getRequiredFactors(level);
  const decision = "CHALLENGE";

  // Structured Audit Log (in-memory buffer)
  const auditEntry = {
    timestamp: new Date().toISOString(),
    email: emailLower,
    riskScore: score,
    riskLevel: level,
    signals,
    requiredFactors,
    decision,
    ip: effectiveIP,
    deviceFingerprint: deviceFingerprint || "unknown",
  };
  riskAuditLogs.push(auditEntry);

  if (level === "CRITICAL" || level === "HIGH") {
    await logAnomaly(emailLower, `ELEVATED_RISK_${level}`, { score, signals });
  }

  // Persist risk event to PostgreSQL
  try {
    await dbRiskEvents.logRiskEvent({
      email: emailLower,
      eventType: "RISK_ASSESSMENT",
      riskScore: score,
      riskLevel: level,
      signals,
      details: { requiredFactors, decision },
      ipAddress: effectiveIP,
    });
  } catch (err) {
    console.error("[RiskEngine] Failed to persist risk event:", err.message);
  }

  console.log(`[RiskEngine] ${emailLower || "anon"} → Score: ${score}/100 (${level}) | Signals: [${signals.map(s => s.name).join(", ") || "NONE"}] | Factors: [${requiredFactors.join(" + ")}]`);

  return {
    score,
    level,
    signals,
    requiredFactors,
    decision,
  };
}

// Backward-compatible wrapper
async function assessRisk(email, deviceFingerprint, currentIP) {
  const result = await evaluateRisk(email, deviceFingerprint, currentIP);
  return { score: result.score, level: result.level };
}

// ── Secure OTP Subsystem (CSPRNG, Hashing, Tracking) ──────────────────────────

function generateSecureOTP() {
  return crypto.randomInt(100000, 1000000).toString();
}

function hashOTP(mfaToken, otp) {
  return crypto
    .createHmac("sha256", OTP_SECRET)
    .update(`${mfaToken}:${otp}`)
    .digest("hex");
}

function verifyOTPHash(mfaToken, candidateOtp, storedHash) {
  if (!candidateOtp || !storedHash) return false;
  const candidateHash = hashOTP(mfaToken, candidateOtp);
  const bufA = Buffer.from(candidateHash, "hex");
  const bufB = Buffer.from(storedHash, "hex");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// ── Session Event Log ─────────────────────────────────────────────────────────

function logSessionEvent(event, jti, userId, email, ip, details = {}) {
  const entry = {
    event,
    jti: jti ? jti.slice(0, 8) + "…" : null,
    userId,
    email,
    ip,
    details,
    timestamp: new Date().toISOString(),
  };
  sessionEvents.push(entry);
  console.log(`[Session] ${event} | user=${email} | jti=${entry.jti}`);
}

// ── Exports ───────────────────────────────────────────────────────────────────
module.exports = {
  // Initialization
  seedUsers,

  // Users (PostgreSQL)
  getUser,
  getUserById,
  createUser,
  updateFaceDescriptor,
  listUsers,

  // Devices (PostgreSQL)
  getDevice,
  getDeviceStatus,
  getUserDevices,
  registerDevice,
  revokeDevice,

  // WebAuthn Credentials (PostgreSQL)
  saveWebAuthnCredential,
  getWebAuthnCredential,
  updateWebAuthnCredential,
  getUserWebAuthnCredentials,

  // WebAuthn Challenges (Redis)
  generateWebAuthnChallenge,
  consumeWebAuthnChallenge,
  peekAndInvalidateWebAuthnChallenge,
  getWebAuthnChallenge,

  // MFA Sessions (Redis)
  createMfaSession,
  getMfaSession,
  updateMfaSession,
  deleteMfaSession,

  // Issued Sessions (PostgreSQL + Redis cache)
  createIssuedSession,
  getIssuedSession,
  revokeSession,
  revokeAllSessions,
  getUserSessions,
  recordSessionContextChange,
  touchSession,

  // Token Blacklist (Redis)
  blacklistToken,
  isTokenBlacklisted,

  // Rate Limiting (Redis)
  recordFailure,
  getFailureCount,
  resetFailures,
  checkRegisterRateLimit,
  getRegisterRemaining,
  checkOtpResendRateLimit,
  getOtpResendRemaining,
  checkDeviceOpRateLimit,
  getDeviceOpRemaining,
  checkWebAuthnRateLimit,
  getWebAuthnRemaining,
  checkGlobalIpRateLimit,
  updateLastLogin,
  recordSessionHijack,
  getHijackHistory,

  // Risk Engine
  evaluateRisk,
  assessRisk,
  getRequiredFactors,
  normalizeIP,

  // OTP
  generateSecureOTP,
  hashOTP,
  verifyOTPHash,

  // Anomaly & Audit (in-memory buffers + PostgreSQL)
  logAnomaly,
  anomalyLogs,
  riskAuditLogs,
  sessionEvents,
  logSessionEvent,

  // PostgreSQL audit/risk/alert repositories
  logAuditEvent,
  getUserAuditLogs,
  logRiskEvent,
  getUserRiskEvents,
  createSecurityAlert,
  getUserAlerts,
  markAlertRead,

  // OTP Store (Redis) — direct passthrough
  otpStore,

  // Session Cache — direct passthrough for middleware
  sessionCache,
};
