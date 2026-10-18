"use strict";

/**
 * VaultBase — Auth Routes  (Phase 10: PostgreSQL + Redis Persistence)
 *
 * All endpoints the Chrome extension consumes.
 * All store calls are now async. No synchronous in-memory paths.
 *
 * Phase 7: WebAuthn routes use @simplewebauthn/server for full
 * cryptographic verification. The private key never leaves the authenticator.
 */

const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const store = require("../store");
const email = require("../email");

const JWT_SECRET =
  process.env.JWT_SECRET || "vaultbase-dev-secret-change-in-prod";
const ACCESS_TTL_S = 3600; // 1 hour
const MFA_TTL_MS = 15 * 60 * 1000; // 15 min
const OTP_TTL_MS = 5 * 60 * 1000; // 5 min
const OTP_RESEND_COOLDOWN_MS = 30 * 1000; // 30 sec
const OTP_MAX_ATTEMPTS = 3;
const OTP_MAX_RESENDS = 3;

// ── WebAuthn RP configuration ─────────────────────────────────────────────────
const RP_ID = process.env.WEBAUTHN_RP_ID || "localhost";
const RP_NAME = process.env.WEBAUTHN_RP_NAME || "VaultBase";
const IS_PRODUCTION = process.env.NODE_ENV === "production";

// Development origins (only used in development mode)
const DEV_ORIGINS = [
  "http://localhost:8080",
  "http://127.0.0.1:8080",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

// Production trusted origins (configured via WEBAUTHN_ORIGINS env var)
// Format: comma-separated list of HTTPS origins
// Example: https://vaultbase.example.com,https://dashboard.vaultbase.example.com
const PROD_ORIGINS = (process.env.WEBAUTHN_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

// Build allowed origins based on environment
const BASE_ORIGINS = IS_PRODUCTION ? PROD_ORIGINS : DEV_ORIGINS;

function getAllowedOrigins(requestOrigin) {
  const origins = new Set([...BASE_ORIGINS]);
  
  // Always allow chrome-extension requests (extension origin is dynamic)
  // In production, this is limited to explicitly configured extension IDs if needed
  if (requestOrigin && /^chrome-extension:\/\//.test(requestOrigin)) {
    origins.add(requestOrigin);
  }
  
  // Allow null origin (Postman/curl) only in development
  if (!IS_PRODUCTION) {
    origins.add(null);
  }
  
  return Array.from(origins);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function ok(res, data, statusCode = 200) {
  return res.status(statusCode).json({ success: true, data });
}

function fail(res, message, statusCode = 400) {
  return res.status(statusCode).json({ success: false, message });
}

async function getSession(mfaToken, res) {
  const session = await store.getMfaSession(mfaToken);
  if (!session) {
    fail(res, "Invalid or expired session", 401);
    return null;
  }
  if (Date.now() > session.expiresAt) {
    await store.deleteMfaSession(mfaToken);
    fail(res, "Session expired — please log in again", 401);
    return null;
  }
  return session;
}

// ── Euclidean distance for face comparison ────────────────────────────────────
function faceDistance(d1, d2) {
  if (!d1 || !d2 || d1.length !== d2.length) return Infinity;
  let sum = 0;
  for (let i = 0; i < d1.length; i++) {
    sum += (d1[i] - d2[i]) ** 2;
  }
  return Math.sqrt(sum);
}

// ── Strict biometric descriptor validation ────────────────────────────────────
function isValidFaceDescriptor(descriptor) {
  if (!Array.isArray(descriptor) || descriptor.length !== 128) {
    return false;
  }
  let sum = 0;
  let sumSq = 0;
  for (let i = 0; i < 128; i++) {
    const val = descriptor[i];
    if (typeof val !== "number" || !Number.isFinite(val) || Number.isNaN(val)) {
      return false;
    }
    sum += val;
    sumSq += val * val;
  }
  const mean = sum / 128;
  const variance = sumSq / 128 - mean * mean;
  if (variance < 0.0001) {
    return false;
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/register
// Body: { email, password, confirmPassword }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/register", async (req, res) => {
  const { email: rawEmail, password, confirmPassword } = req.body || {};

  if (!rawEmail || !password) {
    return fail(res, "Email and password are required");
  }

  const emailLower = rawEmail.toLowerCase().trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLower)) {
    return fail(res, "Invalid email format");
  }

  if (password.length < 8) {
    return fail(res, "Password must be at least 8 characters");
  }

  if (confirmPassword !== undefined && password !== confirmPassword) {
    return fail(res, "Passwords do not match");
  }

  // Check registration rate limit by IP
  const clientIP = req.ip || req.connection?.remoteAddress;
  if (clientIP) {
    const regRateLimit = await store.checkRegisterRateLimit(clientIP);
    if (!regRateLimit.allowed) {
      return res.status(429).json({
        success: false,
        message: "Too many registration attempts from this IP. Please try again later.",
        retryAfter: 3600,
      });
    }
  }

  // Check duplicate
  const existing = await store.getUser(emailLower);
  if (existing) {
    return fail(res, "An account with this email already exists", 409);
  }

  const hash = await bcrypt.hash(password, 10);
  const id = uuidv4();

  await store.createUser({
    id,
    email: emailLower,
    passwordHash: hash,
  });

  // Register the current device as trusted
  const deviceFingerprint = req.headers["x-device-fingerprint"];
  if (deviceFingerprint && deviceFingerprint !== "unknown") {
    await store.registerDevice(emailLower, deviceFingerprint);
  }
  await store.updateLastLogin(emailLower, req.ip);

  console.log(`[Register] New user: ${emailLower} (id: ${id})`);

  return ok(
    res,
    { message: "Account created successfully", email: emailLower },
    201,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/login
// Body: { email, password }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/login", async (req, res) => {
  const { email: rawEmail, password } = req.body || {};
  const deviceFingerprint = req.headers["x-device-fingerprint"] || "unknown";

  if (!rawEmail || !password) {
    return fail(res, "Email and password are required");
  }

  const emailLower = rawEmail.toLowerCase().trim();
  const user = await store.getUser(emailLower);

  // Constant-time path even when user not found
  const dummy = "$2a$10$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const hash = user?.passwordHash || dummy;
  const match = await bcrypt.compare(password, hash);

  if (!user || !match) {
    if (emailLower) {
      await store.recordFailure(emailLower);
      const riskAssessment = await store.evaluateRisk(
        emailLower,
        deviceFingerprint,
        req.ip,
      );
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
        riskScore: riskAssessment.score,
        riskLevel: riskAssessment.level,
        signals: riskAssessment.signals,
      });
    }
    return fail(res, "Invalid email or password", 401);
  }

  // Reset on success
  await store.resetFailures(emailLower);

  const riskAssessment = await store.evaluateRisk(emailLower, deviceFingerprint, req.ip);
  const requiredFactors = riskAssessment.requiredFactors;

  // Update last known IP on successful login
  await store.updateLastLogin(emailLower, req.ip);

  const mfaToken = uuidv4();
  const now = Date.now();

  const sessionData = {
    mfaToken,
    userId: user.id,
    email: user.email,
    riskScore: riskAssessment.score,
    riskLevel: riskAssessment.level,
    signals: riskAssessment.signals,
    requiredFactors,
    completedFactors: [],
    deviceFingerprint,
    createdAt: now,
    expiresAt: now + MFA_TTL_MS,
  };

  await store.createMfaSession(mfaToken, sessionData);

  console.log(
    `[Login] ${emailLower} → risk=${riskAssessment.level} (${riskAssessment.score}), factors=${requiredFactors.join("+")}, token=${mfaToken.slice(0, 8)}…`,
  );

  return ok(res, {
    mfaToken,
    userId: user.id,
    riskScore: riskAssessment.score,
    riskLevel: riskAssessment.level,
    signals: riskAssessment.signals,
    requiredFactors,
    email: user.email,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/send-otp
// Body: { mfaToken }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/send-otp", async (req, res) => {
  const { mfaToken } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  const now = Date.now();

  // 1. Resend cooldown protection (30s)
  if (session.otpLastSentAt && (now - session.otpLastSentAt < OTP_RESEND_COOLDOWN_MS)) {
    const waitSecs = Math.ceil((OTP_RESEND_COOLDOWN_MS - (now - session.otpLastSentAt)) / 1000);
    return res.status(429).json({
      success: false,
      message: `Please wait ${waitSecs}s before requesting a new code.`,
      retryAfter: waitSecs,
    });
  }

  // 2. Maximum resend limit protection (3 resends)
  if ((session.otpResendCount || 0) >= OTP_MAX_RESENDS) {
    return res.status(429).json({
      success: false,
      message: "Maximum OTP requests exceeded. Please sign in again.",
    });
  }

  // 3. Generate cryptographically strong random OTP & hash it
  const otp = store.generateSecureOTP();
  const hashed = store.hashOTP(session.mfaToken, otp);

  // 4. Update session state (invalidate any previous OTP)
  await store.updateMfaSession(mfaToken, {
    otpHash: hashed,
    otpExpiry: now + OTP_TTL_MS,
    otpAttempts: 0,
    otpLastSentAt: now,
    otpResendCount: (session.otpResendCount || 0) + 1,
  });

  console.log(`[OTP] Dispatched secure verification code to ${session.email.split('@')[0][0]}***@${session.email.split('@')[1] || ''}`);

  try {
    await email.sendOTPEmail(session.email, otp, session.email);
  } catch (err) {
    console.error("[OTP] Email dispatch error:", err.message);
  }

  // Never return the OTP in the HTTP response
  return ok(res, {
    message: "Verification code sent to your registered email",
    expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
    cooldownSeconds: Math.floor(OTP_RESEND_COOLDOWN_MS / 1000),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/verify-otp
// Body: { mfaToken, otp }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/verify-otp", async (req, res) => {
  const { mfaToken, otp } = req.body || {};
  if (!mfaToken || !otp) return fail(res, "mfaToken and otp required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  // 1. Check if an active OTP challenge exists
  if (!session.otpHash || !session.otpExpiry) {
    return fail(res, "No active verification code found — please request a new code", 400);
  }

  const now = Date.now();

  // 2. Expiration check
  if (now > session.otpExpiry) {
    await store.updateMfaSession(mfaToken, { otpHash: null, otpExpiry: null });
    return fail(res, "Verification code has expired. Please request a new code.", 401);
  }

  // 3. Check attempt limit
  if ((session.otpAttempts || 0) >= OTP_MAX_ATTEMPTS) {
    await store.updateMfaSession(mfaToken, { otpHash: null, otpExpiry: null });
    await store.recordFailure(session.email);
    return res.status(429).json({
      success: false,
      message: "Too many incorrect attempts. Verification code invalidated. Please request a new code.",
    });
  }

  // 4. Timing-safe cryptographic hash comparison
  const isValid = store.verifyOTPHash(session.mfaToken, otp.toString().trim(), session.otpHash);

  if (!isValid) {
    const newAttempts = (session.otpAttempts || 0) + 1;
    await store.recordFailure(session.email);

    const remainingAttempts = Math.max(0, OTP_MAX_ATTEMPTS - newAttempts);

    // If max attempts reached, immediately destroy the OTP
    if (newAttempts >= OTP_MAX_ATTEMPTS) {
      await store.updateMfaSession(mfaToken, { otpHash: null, otpExpiry: null, otpAttempts: newAttempts });
      return res.status(401).json({
        success: false,
        message: "Too many incorrect attempts. Verification code invalidated. Please request a new code.",
        remainingAttempts: 0,
      });
    }

    await store.updateMfaSession(mfaToken, { otpAttempts: newAttempts });

    const { score, level } = await store.assessRisk(
      session.email,
      session.deviceFingerprint,
      req.ip,
    );
    await store.updateMfaSession(mfaToken, { riskScore: score, riskLevel: level });

    return res.status(401).json({
      success: false,
      message: `Incorrect verification code. ${remainingAttempts} attempt(s) remaining.`,
      remainingAttempts,
      riskScore: score,
      riskLevel: level,
    });
  }

  // 5. Success — Consume OTP immediately (one-time use guarantee)
  const completedFactors = session.completedFactors || [];
  if (!completedFactors.includes("otp")) {
    completedFactors.push("otp");
  }

  await store.updateMfaSession(mfaToken, {
    otpHash: null,
    otpExpiry: null,
    otpAttempts: 0,
    completedFactors,
  });

  console.log(`[OTP] Successfully verified code for ${session.email}`);
  return ok(res, {
    message: "Verification code confirmed",
    completedFactors,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/verify-device
// Body: { mfaToken }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/verify-device", async (req, res) => {
  const { mfaToken } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  const fingerprint = req.headers["x-device-fingerprint"];
  if (!fingerprint || fingerprint === "unknown") {
    return fail(res, "Device fingerprint missing or invalid");
  }

  if (fingerprint !== session.deviceFingerprint) {
    return fail(res, "Device mismatch — fingerprint does not match login", 401);
  }

  const completedFactors = session.completedFactors || [];
  if (!completedFactors.includes("device")) {
    completedFactors.push("device");
  }
  await store.updateMfaSession(mfaToken, { completedFactors });

  console.log(
    `[Device] Verified fingerprint ${fingerprint.slice(0, 8)}… for ${session.email}`,
  );
  return ok(res, { message: "Device fingerprint verified", fingerprint });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/verify-face
// Body: { mfaToken, descriptor: number[] }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/verify-face", async (req, res) => {
  const { mfaToken, descriptor } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  const user = await store.getUserById(session.userId);
  if (!user) return fail(res, "User not found", 404);

  // Strict descriptor validation
  if (!isValidFaceDescriptor(descriptor)) {
    await store.logAnomaly(session.email, "INVALID_FACE_DESCRIPTOR", {
      ip: req.ip,
      descriptorType: typeof descriptor,
      isArray: Array.isArray(descriptor),
      length: Array.isArray(descriptor) ? descriptor.length : 0,
    });
    return fail(res, "Invalid biometric face descriptor — valid 128-dimensional vector required", 400);
  }

  // Parse faceDescriptor if it's stored as JSON string
  let storedDescriptor = user.faceDescriptor;
  if (typeof storedDescriptor === 'string') {
    try {
      storedDescriptor = JSON.parse(storedDescriptor);
    } catch (e) {
      storedDescriptor = null;
    }
  }

  // ── First-time enrollment: save descriptor ────────────────────────────────
  if (!storedDescriptor) {
    await store.updateFaceDescriptor(user.id, descriptor);
    console.log(`[Face] Enrolled biometric face descriptor for ${user.email}`);

    const completedFactors = session.completedFactors || [];
    if (!completedFactors.includes("face")) {
      completedFactors.push("face");
    }
    await store.updateMfaSession(mfaToken, { completedFactors });
    return ok(res, { message: "Face enrolled and verified", enrolled: true });
  }

  // ── Subsequent logins: compare descriptors ────────────────────────────────
  const dist = faceDistance(storedDescriptor, descriptor);
  const THRESHOLD = 0.5;

  console.log(
    `[Face] Distance for ${user.email}: ${dist.toFixed(4)} (threshold: ${THRESHOLD})`,
  );

  if (dist > THRESHOLD) {
    await store.recordFailure(session.email);
    await store.logAnomaly(session.email, "FACE_VERIFICATION_MISMATCH", {
      distance: parseFloat(dist.toFixed(4)),
      threshold: THRESHOLD,
      ip: req.ip,
    });
    return fail(res, `Face not recognized (distance: ${dist.toFixed(3)})`, 401);
  }

  const completedFactors = session.completedFactors || [];
  if (!completedFactors.includes("face")) {
    completedFactors.push("face");
  }
  await store.updateMfaSession(mfaToken, { completedFactors });

  return ok(res, { message: "Face verified", distance: dist });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/webauthn-register-options
// Body: { mfaToken }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/webauthn-register-options", async (req, res) => {
  const { mfaToken } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  const user = await store.getUserById(session.userId);
  if (!user) return fail(res, "User not found", 404);

  // Check WebAuthn rate limit
  const waRateLimit = await store.checkWebAuthnRateLimit(user.email);
  if (!waRateLimit.allowed) {
    return res.status(429).json({
      success: false,
      message: "Too many WebAuthn operations. Please try again later.",
      retryAfter: 3600,
    });
  }

  const existingCredentials = await store.getUserWebAuthnCredentials(user.id);
  const excludeCredentials = existingCredentials.map((c) => ({
    id: c.credentialId,
    type: "public-key",
    transports: c.transports,
  }));

  let options;
  try {
    options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: user.id,
      userName: user.email,
      userDisplayName: user.email,
      timeout: 60000,
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "preferred",
        userVerification: "required",
      },
      supportedAlgorithmIDs: [-7, -257],
    });
  } catch (err) {
    console.error("[WebAuthn] generateRegistrationOptions error:", err);
    return fail(res, "Failed to generate registration options", 500);
  }

  // Store challenge: short-lived, single-use, user-bound
  const challengeBase64url = Buffer.from(options.challenge).toString("base64url");
  
  // Store via Redis webauthn store
  await store.generateWebAuthnChallenge(mfaToken, user.id, 'registration');
  
  // Get the challenge we stored and use it (or override with our own)
  const storedChallenge = await store.getWebAuthnChallenge(mfaToken);
  if (storedChallenge) {
    options.challenge = storedChallenge.challenge;
  } else {
    options.challenge = challengeBase64url;
  }

  console.log(
    `[WebAuthn] Registration options generated for ${user.email}`,
  );

  return ok(res, {
    options,
    rpId: RP_ID,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/webauthn-register-verify
// Body: { mfaToken, credential }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/webauthn-register-verify", async (req, res) => {
  const { mfaToken, credential } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");
  if (!credential) return fail(res, "credential required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  const user = await store.getUserById(session.userId);
  if (!user) return fail(res, "User not found", 404);

  // Consume the challenge — single-use, TTL checked, user binding checked
  const expectedChallenge = await store.consumeWebAuthnChallenge(mfaToken, user.id);
  if (!expectedChallenge) {
    await store.logAnomaly(session.email, "WEBAUTHN_INVALID_CHALLENGE", {
      ip: req.ip,
      reason: "Challenge missing, expired, already used, or user mismatch",
    });
    return fail(res, "WebAuthn challenge is invalid or expired — please try again", 400);
  }

  const requestOrigin = req.headers.origin || req.headers.referer || "";
  const expectedOrigins = getAllowedOrigins(requestOrigin);

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
  } catch (err) {
    console.error("[WebAuthn] verifyRegistrationResponse error:", err.message);
    await store.logAnomaly(session.email, "WEBAUTHN_REGISTRATION_FAILED", {
      ip: req.ip,
      error: err.message,
    });
    return fail(res, `WebAuthn registration verification failed: ${err.message}`, 400);
  }

  if (!verification.verified || !verification.registrationInfo) {
    await store.logAnomaly(session.email, "WEBAUTHN_REGISTRATION_FAILED", {
      ip: req.ip,
      reason: "Verification returned false",
    });
    return fail(res, "WebAuthn registration could not be verified", 400);
  }

  const { registrationInfo } = verification;

  // Store the credential — public key in base64url, never the private key
  let storedCred;
  try {
    storedCred = await store.saveWebAuthnCredential(user.id, {
      credentialId: registrationInfo.credentialID,
      publicKey: Buffer.from(registrationInfo.credentialPublicKey).toString("base64url"),
      signCount: registrationInfo.counter,
      transports: credential.response?.transports ?? [],
      deviceType: registrationInfo.credentialDeviceType,
      backedUp: registrationInfo.credentialBackedUp,
    });
  } catch (err) {
    if (err.message === "Credential already registered" || (err.code === '23505')) {
      return fail(res, "This authenticator is already registered", 409);
    }
    throw err;
  }

  console.log(
    `[WebAuthn] Credential enrolled for ${user.email}: ${storedCred.credentialId.slice(0, 16)}…`,
  );

  return ok(res, {
    message: "WebAuthn authenticator registered successfully",
    credentialId: storedCred.credentialId,
    deviceType: storedCred.deviceType,
    backedUp: storedCred.backedUp,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/webauthn-challenge
// Body: { mfaToken, userId }
//
// DEPRECATED path kept for backwards compatibility.
// ─────────────────────────────────────────────────────────────────────────────
router.post("/webauthn-challenge", async (req, res) => {
  return webauthnAuthOptionsHandler(req, res);
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/webauthn-auth-options
// Body: { mfaToken }
// ─────────────────────────────────────────────────────────────────────────────
async function webauthnAuthOptionsHandler(req, res) {
  const { mfaToken } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  const user = await store.getUserById(session.userId);
  if (!user) return fail(res, "User not found", 404);

  // Check WebAuthn rate limit
  const waRateLimit = await store.checkWebAuthnRateLimit(user.email);
  if (!waRateLimit.allowed) {
    return res.status(429).json({
      success: false,
      message: "Too many WebAuthn operations. Please try again later.",
      retryAfter: 3600,
    });
  }

  const existingCredentials = await store.getUserWebAuthnCredentials(user.id);

  const allowCredentials = existingCredentials.map((c) => ({
    id: c.credentialId,
    type: "public-key",
    transports: c.transports && c.transports.length > 0
      ? c.transports
      : ["internal", "hybrid"],
  }));

  let options;
  try {
    options = await generateAuthenticationOptions({
      rpID: RP_ID,
      timeout: 60000,
      allowCredentials,
      userVerification: "required",
    });
  } catch (err) {
    console.error("[WebAuthn] generateAuthenticationOptions error:", err);
    return fail(res, "Failed to generate authentication options", 500);
  }

  // Store challenge via Redis
  const challenge = await store.generateWebAuthnChallenge(mfaToken, user.id, 'authentication');
  options.challenge = challenge;

  console.log(
    `[WebAuthn] Auth challenge issued for ${user.email}, credentials: ${allowCredentials.length}`,
  );

  return ok(res, {
    options,
    challenge,
    rpId: RP_ID,
    allowCredentials,
    userVerification: "required",
    timeout: 60000,
  });
}

router.post("/webauthn-auth-options", webauthnAuthOptionsHandler);

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/webauthn-verify
// Body: { mfaToken, assertion }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/webauthn-verify", async (req, res) => {
  const { mfaToken, assertion } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");
  if (!assertion) return fail(res, "assertion required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  const user = await store.getUserById(session.userId);
  if (!user) return fail(res, "User not found", 404);

  // 1. Reject fake "success" flags
  if (!assertion.response || !assertion.response.clientDataJSON || !assertion.response.authenticatorData || !assertion.response.signature) {
    await store.logAnomaly(session.email, "WEBAUTHN_FAKE_ASSERTION", {
      ip: req.ip,
      reason: "Assertion missing required cryptographic fields",
      hasResponse: !!assertion.response,
    });
    return fail(res, "Invalid WebAuthn assertion — cryptographic response fields required", 400);
  }

  // 2. Consume the challenge (single-use, TTL, user-bound)
  const expectedChallenge = await store.consumeWebAuthnChallenge(mfaToken, user.id);
  if (!expectedChallenge) {
    await store.logAnomaly(session.email, "WEBAUTHN_INVALID_CHALLENGE", {
      ip: req.ip,
      reason: "Challenge missing, expired, already used, or user mismatch",
    });
    return fail(res, "WebAuthn challenge is invalid or expired — please try again", 400);
  }

  // 3. Verify credential ownership
  const credentialId = assertion.id;
  if (!credentialId) {
    return fail(res, "Assertion missing credential ID", 400);
  }

  const storedCredential = await store.getWebAuthnCredential(user.id, credentialId);
  if (!storedCredential) {
    await store.logAnomaly(session.email, "WEBAUTHN_UNKNOWN_CREDENTIAL", {
      ip: req.ip,
      credentialId: credentialId?.slice(0, 20),
    });
    return fail(res, "Credential not registered for this user", 401);
  }

  // 4. Cryptographic assertion verification
  const requestOrigin = req.headers.origin || req.headers.referer || "";
  const expectedOrigins = getAllowedOrigins(requestOrigin);

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      authenticator: {
        credentialID: storedCredential.credentialId,
        credentialPublicKey: Buffer.from(storedCredential.publicKey, "base64url"),
        counter: storedCredential.signCount,
        transports: storedCredential.transports,
      },
    });
  } catch (err) {
    console.error("[WebAuthn] verifyAuthenticationResponse error:", err.message);
    await store.logAnomaly(session.email, "WEBAUTHN_VERIFICATION_FAILED", {
      ip: req.ip,
      credentialId: credentialId?.slice(0, 20),
      error: err.message,
    });
    return fail(res, `WebAuthn verification failed: ${err.message}`, 401);
  }

  if (!verification.verified) {
    await store.logAnomaly(session.email, "WEBAUTHN_VERIFICATION_FAILED", {
      ip: req.ip,
      reason: "Verification returned false",
    });
    return fail(res, "WebAuthn assertion could not be verified", 401);
  }

  const { authenticationInfo } = verification;

  // 5. Sign counter check (replay / authenticator clone detection)
  if (
    authenticationInfo.newCounter > 0 &&
    storedCredential.signCount > 0 &&
    authenticationInfo.newCounter <= storedCredential.signCount
  ) {
    await store.logAnomaly(session.email, "WEBAUTHN_COUNTER_ANOMALY", {
      ip: req.ip,
      credentialId: credentialId?.slice(0, 20),
      storedCounter: storedCredential.signCount,
      receivedCounter: authenticationInfo.newCounter,
    });
    return fail(res, "WebAuthn sign counter anomaly detected — possible replay or cloned authenticator", 401);
  }

  // 6. Update credential state
  await store.updateWebAuthnCredential(user.id, credentialId, {
    newSignCount: authenticationInfo.newCounter,
    backedUp: authenticationInfo.credentialBackedUp,
  });

  // 7. Mark factor as completed
  const completedFactors = session.completedFactors || [];
  if (!completedFactors.includes("webauthn")) {
    completedFactors.push("webauthn");
  }
  await store.updateMfaSession(mfaToken, { completedFactors });

  console.log(
    `[WebAuthn] Assertion verified for ${user.email} (counter: ${storedCredential.signCount} → ${authenticationInfo.newCounter})`,
  );

  return ok(res, {
    message: "WebAuthn authentication verified",
    credentialId: storedCredential.credentialId,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/verify-fingerprint
// Body: { mfaToken, assertion }
//
// LEGACY endpoint — delegates to /webauthn-verify logic.
// ─────────────────────────────────────────────────────────────────────────────
router.post("/verify-fingerprint", async (req, res) => {
  const { mfaToken, assertion } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");
  if (!assertion) return fail(res, "assertion required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  const user = await store.getUserById(session.userId);
  if (!user) return fail(res, "User not found", 404);

  // Reject fake "success" flags
  if (!assertion.response || !assertion.response.clientDataJSON ||
      !assertion.response.authenticatorData || !assertion.response.signature) {
    await store.logAnomaly(session.email, "WEBAUTHN_FAKE_ASSERTION", {
      ip: req.ip,
      reason: "Assertion missing required cryptographic fields",
    });
    return fail(res, "Invalid WebAuthn assertion — cryptographic response fields required", 400);
  }

  const expectedChallenge = await store.consumeWebAuthnChallenge(mfaToken, user.id);
  if (!expectedChallenge) {
    await store.logAnomaly(session.email, "WEBAUTHN_INVALID_CHALLENGE", {
      ip: req.ip,
      reason: "Challenge missing, expired, already used, or user mismatch",
    });
    return fail(res, "WebAuthn challenge is invalid or expired — please try again", 400);
  }

  const credentialId = assertion.id;
  if (!credentialId) return fail(res, "Assertion missing credential ID", 400);

  const storedCredential = await store.getWebAuthnCredential(user.id, credentialId);
  if (!storedCredential) {
    await store.logAnomaly(session.email, "WEBAUTHN_UNKNOWN_CREDENTIAL", {
      ip: req.ip,
      credentialId: credentialId?.slice(0, 20),
    });
    return fail(res, "Credential not registered for this user", 401);
  }

  const requestOrigin = req.headers.origin || req.headers.referer || "";
  const expectedOrigins = getAllowedOrigins(requestOrigin);

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      authenticator: {
        credentialID: storedCredential.credentialId,
        credentialPublicKey: Buffer.from(storedCredential.publicKey, "base64url"),
        counter: storedCredential.signCount,
        transports: storedCredential.transports,
      },
    });
  } catch (err) {
    console.error("[WebAuthn] verify-fingerprint error:", err.message);
    await store.logAnomaly(session.email, "WEBAUTHN_VERIFICATION_FAILED", {
      ip: req.ip,
      error: err.message,
    });
    return fail(res, `WebAuthn verification failed: ${err.message}`, 401);
  }

  if (!verification.verified) {
    return fail(res, "WebAuthn assertion could not be verified", 401);
  }

  const { authenticationInfo } = verification;

  if (
    authenticationInfo.newCounter > 0 &&
    storedCredential.signCount > 0 &&
    authenticationInfo.newCounter <= storedCredential.signCount
  ) {
    await store.logAnomaly(session.email, "WEBAUTHN_COUNTER_ANOMALY", {
      ip: req.ip,
      storedCounter: storedCredential.signCount,
      receivedCounter: authenticationInfo.newCounter,
    });
    return fail(res, "WebAuthn sign counter anomaly — possible replay", 401);
  }

  await store.updateWebAuthnCredential(user.id, credentialId, {
    newSignCount: authenticationInfo.newCounter,
    backedUp: authenticationInfo.credentialBackedUp,
  });

  const completedFactors = session.completedFactors || [];
  if (!completedFactors.includes("webauthn")) {
    completedFactors.push("webauthn");
  }
  if (!completedFactors.includes("fingerprint")) {
    completedFactors.push("fingerprint");
  }
  await store.updateMfaSession(mfaToken, { completedFactors });

  console.log(`[WebAuthn] Verified via /verify-fingerprint for ${user.email}`);

  return ok(res, { message: "WebAuthn authentication verified" });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/issue-tokens
// Body: { mfaToken }
// ─────────────────────────────────────────────────────────────────────────────
router.post("/issue-tokens", async (req, res) => {
  const { mfaToken } = req.body || {};
  if (!mfaToken) return fail(res, "mfaToken required");

  const session = await getSession(mfaToken, res);
  if (!session) return;

  // Verify all required factors completed
  const missing = session.requiredFactors.filter(
    (f) => !(session.completedFactors || []).includes(f),
  );
  if (missing.length > 0) {
    return fail(res, `MFA incomplete — missing: ${missing.join(", ")}`, 403);
  }

  const user = await store.getUserById(session.userId);
  if (!user) return fail(res, "User not found", 404);

  // Issue JWT access token
  const jti = uuidv4();
  const userAgent = (req.headers["user-agent"] || "").slice(0, 256);

  const payload = {
    jti,
    iss: "vaultbase",
    sub: user.id,
    email: user.email,
    riskLevel: session.riskLevel,
    factors: session.completedFactors,
    fingerprint: session.deviceFingerprint,
    ip: req.ip,
    ua: userAgent.slice(0, 64),
    iat: Math.floor(Date.now() / 1000),
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: ACCESS_TTL_S,
  });

  // Register in server-side session store (PostgreSQL + Redis cache)
  await store.createIssuedSession(jti, {
    userId: user.id,
    email: user.email,
    deviceFp: session.deviceFingerprint,
    ip: req.ip,
    userAgent,
    accessTtlMs: ACCESS_TTL_S * 1000,
  });

  // Set HttpOnly secure cookie (Secure flag only in production HTTPS)
  const isProduction = process.env.NODE_ENV === 'production';
  res.cookie("vaultbase_token", accessToken, {
    httpOnly: true,
    sameSite: isProduction ? "None" : "Lax",
    secure: isProduction,
    maxAge: ACCESS_TTL_S * 1000,
  });

  // Invalidate MFA session
  await store.deleteMfaSession(mfaToken);

  // Promote/update device as trusted upon successful authentication
  if (session.deviceFingerprint && session.deviceFingerprint !== "unknown") {
    await store.registerDevice(user.email, session.deviceFingerprint, "Verified Device", req.ip);
  }

  // Log audit event
  await store.logAuditEvent({
    userId: user.id,
    email: user.email,
    eventType: "LOGIN_SUCCESS",
    status: "SUCCESS",
    ipAddress: req.ip,
    details: {
      riskLevel: session.riskLevel,
      factors: session.completedFactors,
      jti: jti.slice(0, 8) + "…",
    },
  });

  console.log(
    `[Token] Issued access token for ${user.email} (${session.riskLevel}) jti=${jti.slice(0, 8)}…`,
  );

  return ok(res, {
    accessToken,
    tokenType: "Bearer",
    expiresIn: ACCESS_TTL_S,
    userId: user.id,
    email: user.email,
    riskLevel: session.riskLevel,
    factors: session.completedFactors,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /auth/devices
// Query: ?email=... or Bearer Token
// ─────────────────────────────────────────────────────────────────────────────
// ── Authentication Helper Middleware for Protected Auth Routes ──────────────
async function requireAuth(req, res, next) {
  if (req.user && req.user.sub) {
    return next();
  }

  const authHeader = req.headers.authorization;
  const token = (authHeader && authHeader.split(" ")[1]) || req.cookies?.vaultbase_token;

  if (!token) {
    return fail(res, "Authentication required", 401);
  }

  const tokenBlacklisted = await store.isTokenBlacklisted(token);
  if (tokenBlacklisted) {
    return res.status(401).json({ success: false, message: "SESSION_REVOKED", code: "REVOKED-401" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: "vaultbase",
    });

    if (decoded.jti) {
      const jtiBlacklisted = await store.isTokenBlacklisted(decoded.jti);
      if (jtiBlacklisted) {
        return res.status(401).json({ success: false, message: "SESSION_REVOKED", code: "REVOKED-401" });
      }
    }

    const sessionRec = decoded.jti ? await store.getIssuedSession(decoded.jti) : null;
    if (sessionRec) {
      if (sessionRec.status === "revoked") {
        return res.status(401).json({ success: false, message: "SESSION_REVOKED", code: "REVOKED-401" });
      }
      if (sessionRec.status === "expired") {
        return res.status(401).json({ success: false, message: "SESSION_EXPIRED", code: "EXPIRED-401" });
      }
    }

    req.user = decoded;
    req.sessionRecord = sessionRec;
    next();
  } catch (err) {
    return fail(res, `Invalid or expired token: ${err.message}`, 401);
  }
}

router.get("/devices", async (req, res) => {
  let emailAddr = req.query.email;

  const authHeader = req.headers.authorization;
  const token = (authHeader && authHeader.split(" ")[1]) || req.cookies?.vaultbase_token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: ["HS256"],
        issuer: "vaultbase",
      });
      if (decoded && decoded.email) emailAddr = decoded.email;
    } catch {}
  }

  if (!emailAddr) {
    return fail(res, "Authentication or email required to view devices", 401);
  }

  const deviceList = await store.getUserDevices(emailAddr);
  return ok(res, { devices: deviceList });
});

router.post("/devices/revoke", async (req, res) => {
  let { email: emailAddr, deviceId, fingerprint } = req.body || {};

  const authHeader = req.headers.authorization;
  const token = (authHeader && authHeader.split(" ")[1]) || req.cookies?.vaultbase_token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: ["HS256"],
        issuer: "vaultbase",
      });
      if (decoded && decoded.email) emailAddr = decoded.email;
    } catch {}
  }

  if (!emailAddr) {
    return fail(res, "Authentication or email required to revoke device", 401);
  }

  // Check device operation rate limit
  const devOpLimit = await store.checkDeviceOpRateLimit(emailAddr);
  if (!devOpLimit.allowed) {
    return res.status(429).json({
      success: false,
      message: "Too many device operations. Please try again later.",
      retryAfter: 3600,
    });
  }

  const target = fingerprint || deviceId;
  if (!target) {
    return fail(res, "deviceId or fingerprint required");
  }

  const success = await store.revokeDevice(emailAddr, target);
  if (!success) {
    return fail(res, "Device not found for this user", 404);
  }

  const emitSecurityEvent = req.app.get("emitSecurityEvent");
  if (emitSecurityEvent) {
    const userObj = await store.getUser(emailAddr);
    if (userObj) {
      emitSecurityEvent(userObj.id, "device:revoked", {
        target,
        email: emailAddr,
        reason: "User revoked device from dashboard",
      });
    }
  }

  return ok(res, { message: "Device successfully revoked", target });
});

// ── Phase 8: Session Management Endpoints ────────────────────────────────────

router.post("/logout", requireAuth, async (req, res) => {
  const authHeader = req.headers.authorization;
  const rawToken = (authHeader && authHeader.split(" ")[1]) || req.cookies?.vaultbase_token;

  if (rawToken) {
    await store.blacklistToken(rawToken);
  }

  if (req.user && req.user.jti) {
    await store.revokeSession(req.user.jti, "logout");
  }

  const emitSecurityEvent = req.app.get("emitSecurityEvent");
  if (emitSecurityEvent && req.user?.sub) {
    emitSecurityEvent(req.user.sub, "session:revoked", {
      jti: req.user.jti,
      reason: "logout",
    });
  }

  // Clear cookie with matching options
  const isProduction = process.env.NODE_ENV === 'production';
  res.clearCookie("vaultbase_token", {
    httpOnly: true,
    sameSite: isProduction ? "None" : "Lax",
    secure: isProduction,
  });
  return ok(res, { message: "Logged out successfully" });
});

router.get("/sessions", requireAuth, async (req, res) => {
  const userSessions = await store.getUserSessions(req.user.sub);
  return ok(res, { sessions: userSessions });
});

router.post("/sessions/revoke", requireAuth, async (req, res) => {
  const { jti } = req.body || {};
  if (!jti) return fail(res, "jti required");

  const targetSession = await store.getIssuedSession(jti);
  if (!targetSession || targetSession.userId !== req.user.sub) {
    return fail(res, "Session not found or not owned by user", 404);
  }

  await store.revokeSession(jti, "user-requested");

  const emitSecurityEvent = req.app.get("emitSecurityEvent");
  if (emitSecurityEvent) {
    emitSecurityEvent(req.user.sub, "session:revoked", {
      jti,
      reason: "user-requested",
    });
  }

  return ok(res, { message: "Session revoked successfully", jti });
});

router.post("/sessions/revoke-all", requireAuth, async (req, res) => {
  const revokedCount = await store.revokeAllSessions(req.user.sub, "user-revoke-all");

  const emitSecurityEvent = req.app.get("emitSecurityEvent");
  if (emitSecurityEvent) {
    emitSecurityEvent(req.user.sub, "session:revoked", {
      reason: "user-revoke-all",
      revokedCount,
    });
  }

  return ok(res, { message: "All sessions revoked successfully", revokedCount });
});

router.get("/session", requireAuth, async (req, res) => {
  const currentSession = req.user.jti ? await store.getIssuedSession(req.user.jti) : null;
  return ok(res, {
    user: {
      id: req.user.sub,
      email: req.user.email,
      riskLevel: req.user.riskLevel,
      factors: req.user.factors,
    },
    session: currentSession,
  });
});

// ── Phase 9: Security Dashboard Aggregation Endpoints ─────────────────────────

router.get("/overview", requireAuth, async (req, res) => {
  const userId = req.user.sub;
  const emailAddr = req.user.email;
  const user = await store.getUser(emailAddr);

  // 1. Sessions summary
  const userSessions = await store.getUserSessions(userId);
  const activeSessions = userSessions.filter((s) => s.status === "active");

  // 2. Devices summary
  const userDevices = await store.getUserDevices(emailAddr);
  const trustedDevices = userDevices.filter((d) => d.isTrusted && !d.isRevoked);
  const revokedDevices = userDevices.filter((d) => d.isRevoked);

  // 3. Biometric profiles
  const webauthnCreds = await store.getUserWebAuthnCredentials(userId);
  const biometrics = {
    faceEnrolled: !!(user && user.faceDescriptor),
    webauthnCredentialsCount: webauthnCreds.length,
  };

  // 4. Latest risk evaluation
  const latestAuditLog = [...store.riskAuditLogs]
    .reverse()
    .find((l) => l.email === emailAddr);

  const risk = {
    score: latestAuditLog ? latestAuditLog.riskScore : (req.user.riskLevel === "CRITICAL" ? 90 : (req.user.riskLevel === "HIGH" ? 65 : (req.user.riskLevel === "MEDIUM" ? 45 : 0))),
    level: latestAuditLog ? latestAuditLog.riskLevel : (req.user.riskLevel || "LOW"),
    lastEvaluatedAt: latestAuditLog ? latestAuditLog.timestamp : new Date().toISOString(),
  };

  // 5. Recent security events
  const userAnomalies = store.anomalyLogs
    .filter((a) => a.email === emailAddr)
    .map((a) => ({
      id: "anomaly-" + a.timestamp,
      type: a.type,
      category: "ANOMALY",
      details: a.details,
      timestamp: a.timestamp,
      severity: a.type.includes("CRITICAL") || a.type.includes("HIJACK") ? "CRITICAL" : (a.type.includes("HIGH") ? "HIGH" : "MEDIUM"),
    }));

  const userSessionEvents = store.sessionEvents
    .filter((e) => e.email === emailAddr)
    .map((e) => ({
      id: "sess-event-" + e.timestamp + "-" + (e.jti || ""),
      type: e.event,
      category: "SESSION",
      details: e.details,
      timestamp: e.timestamp,
      severity: e.event.includes("HIJACK") ? "CRITICAL" : (e.event.includes("REVOKED") ? "HIGH" : "LOW"),
    }));

  const userAuditEvents = store.riskAuditLogs
    .filter((l) => l.email === emailAddr)
    .map((l) => ({
      id: "audit-" + l.timestamp,
      type: "AUTH_RISK_ASSESSMENT",
      category: "AUTH",
      details: { riskScore: l.riskScore, riskLevel: l.riskLevel, signals: l.signals, factors: l.requiredFactors },
      timestamp: l.timestamp,
      severity: l.riskLevel,
    }));

  const allRecent = [...userAnomalies, ...userSessionEvents, ...userAuditEvents]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 10);

  // 6. Active security alerts
  const alerts = userAnomalies
    .filter((a) => a.severity === "CRITICAL" || a.severity === "HIGH")
    .slice(0, 5);

  return ok(res, {
    user: {
      id: userId,
      email: emailAddr,
      riskLevel: risk.level,
      factors: req.user.factors || ["otp"],
    },
    sessions: {
      activeCount: activeSessions.length,
      totalCount: userSessions.length,
      currentJti: req.user.jti || null,
    },
    devices: {
      trustedCount: trustedDevices.length,
      revokedCount: revokedDevices.length,
      totalCount: userDevices.length,
    },
    biometrics,
    risk,
    recentEvents: allRecent,
    alerts,
  });
});

router.get("/audit-logs", requireAuth, async (req, res) => {
  const emailAddr = req.user.email;
  const logs = store.riskAuditLogs
    .filter((l) => l.email === emailAddr)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .map((l) => ({
      timestamp: l.timestamp,
      email: l.email,
      riskScore: l.riskScore,
      riskLevel: l.riskLevel,
      signals: l.signals,
      requiredFactors: l.requiredFactors,
      decision: l.decision,
      ip: l.ip,
      deviceFingerprint: l.deviceFingerprint ? l.deviceFingerprint.slice(0, 16) + "…" : "unknown",
    }));

  return ok(res, { logs });
});

router.get("/risk-events", requireAuth, async (req, res) => {
  const emailAddr = req.user.email;
  const userAnomalies = store.anomalyLogs
    .filter((a) => a.email === emailAddr)
    .map((a) => ({
      type: a.type,
      category: "ANOMALY",
      details: a.details,
      timestamp: a.timestamp,
    }));

  const userSessionEvents = store.sessionEvents
    .filter((e) => e.email === emailAddr)
    .map((e) => ({
      type: e.event,
      category: "SESSION_EVENT",
      details: e.details,
      timestamp: e.timestamp,
      jti: e.jti,
    }));

  const events = [...userAnomalies, ...userSessionEvents].sort(
    (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
  );

  return ok(res, { events });
});

module.exports = router;
