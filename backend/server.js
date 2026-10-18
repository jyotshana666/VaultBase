'use strict';

require('dotenv').config();
const http         = require('http');
const express      = require('express');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const path         = require('path');
const jwt          = require('jsonwebtoken');
const { Server }   = require('socket.io');

const authRoutes   = require('./routes/auth');
const store        = require('./store');

// ── Database & Redis initialization ──────────────────────────────────────────
const { checkHealth: checkDbHealth } = require('./db/pool');
const { initSchema }  = require('./db/init');
const { getRedisClient, checkHealth: checkRedisHealth } = require('./redis/client');

const app  = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'vaultbase-dev-secret-change-in-prod';

const server = http.createServer(app);

// ── Real-Time Socket.io Server for Security Events ───────────────────────────
const io = new Server(server, {
  cors: {
    origin: (origin, cb) => cb(null, true),
    credentials: true,
    methods: ['GET', 'POST'],
  }
});

// Socket.io JWT Authentication Middleware & User Rooms
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  if (!token) {
    return next(new Error('Authentication token required'));
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'vaultbase',
    });
    socket.user = decoded;
    next();
  } catch (err) {
    return next(new Error('Authentication failed: ' + err.message));
  }
});

io.on('connection', (socket) => {
  if (socket.user && socket.user.sub) {
    const userRoom = `user:${socket.user.sub}`;
    socket.join(userRoom);
    console.log(`[Socket] User ${socket.user.email} joined ${userRoom} (socket ${socket.id})`);
  }
});

function emitSecurityEvent(userId, eventName, payload = {}) {
  if (io && userId) {
    const eventData = {
      event: eventName,
      userId,
      ...payload,
      timestamp: new Date().toISOString(),
    };
    io.to(`user:${userId}`).emit(eventName, eventData);
    io.to(`user:${userId}`).emit('security:event', eventData);
    console.log(`[Socket] Emitted "${eventName}" to user:${userId}`);
  }
}

app.set('io', io);
app.set('emitSecurityEvent', emitSecurityEvent);

// ── CORS — allow extension + demo site + dashboard ───────────────────────────
app.use(cors({
  origin: (origin, cb) => {
    const allowed = [
      'http://localhost:8080',
      'http://127.0.0.1:8080',
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      null, // Postman / curl
    ];
    if (!origin || allowed.includes(origin) || /^chrome-extension:\/\//.test(origin)) {
      return cb(null, true);
    }
    cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Device-Fingerprint', 'Authorization']
}));

app.options('*', cors());

// ── Body / Cookie parsers ─────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// ── Session Hijack Detection & Security Middleware (async) ───────────────────
app.use(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const tokenFromCookie = req.cookies.vaultbase_token;
  const token = (authHeader && authHeader.split(' ')[1]) || tokenFromCookie;

  if (!token) return next();

  // Check raw token blacklist
  const tokenBlacklisted = await store.isTokenBlacklisted(token);
  if (tokenBlacklisted) {
    return res.status(401).json({ success: false, message: 'SESSION_REVOKED', code: 'BLACK-401' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'vaultbase',
    });

    // Check blacklist by JTI
    if (decoded.jti) {
      const jtiBlacklisted = await store.isTokenBlacklisted(decoded.jti);
      if (jtiBlacklisted) {
        return res.status(401).json({ success: false, message: 'SESSION_REVOKED', code: 'REVOKED-401' });
      }
    }

    // Server-side session record check (PostgreSQL authoritative, Redis fast-path)
    const sessionRec = decoded.jti ? await store.getIssuedSession(decoded.jti) : null;
    if (sessionRec) {
      if (sessionRec.status === 'revoked') {
        return res.status(401).json({ success: false, message: 'SESSION_REVOKED', code: 'REVOKED-401' });
      }
      if (sessionRec.status === 'expired') {
        return res.status(401).json({ success: false, message: 'SESSION_EXPIRED', code: 'EXPIRED-401' });
      }
    }

    const currentFingerprint = req.headers['x-device-fingerprint'];
    const currentIP = req.ip;
    const currentUA = (req.headers['user-agent'] || '').slice(0, 64);

    // 1. Check if the device presenting the session has been revoked
    if (currentFingerprint && currentFingerprint !== 'unknown') {
      const devStatus = await store.getDeviceStatus(decoded.email, currentFingerprint);
      if (devStatus === 'REVOKED') {
        if (decoded.jti) await store.revokeSession(decoded.jti, 'revoked_device_reuse');
        await store.blacklistToken(token);
        await store.logAnomaly(decoded.email, 'REVOKED_DEVICE_REUSE', {
          ip: currentIP,
          fingerprint: currentFingerprint,
          jti: decoded.jti ? decoded.jti.slice(0, 8) + '…' : null,
        });
        emitSecurityEvent(decoded.sub, 'device:revoked', {
          fingerprint: currentFingerprint,
          reason: 'Revoked device attempted session reuse',
          ip: currentIP,
        });
        return res.status(401).json({ success: false, message: 'REVOKED_DEVICE_SESSION_REJECTED', code: 'REVOKED-DEVICE-401' });
      }
    }

    // 2. Fingerprint mismatch — Session Hijack suspected
    const fpMismatch = decoded.fingerprint && currentFingerprint && currentFingerprint !== 'unknown' && decoded.fingerprint !== currentFingerprint;
    const ipMismatch = decoded.ip && currentIP && decoded.ip !== currentIP;
    const uaMismatch = decoded.ua && currentUA && decoded.ua !== currentUA;

    if (fpMismatch) {
      if (decoded.jti) await store.revokeSession(decoded.jti, 'hijack');
      await store.blacklistToken(token);
      await store.recordSessionHijack(decoded.email);
      await store.logAnomaly(decoded.email, 'SESSION_HIJACK', {
        reason: ipMismatch ? 'Fingerprint + IP mismatch (HIGH)' : 'Fingerprint mismatch (MEDIUM)',
        oldIP: decoded.ip,
        newIP: currentIP,
        oldFP: decoded.fingerprint,
        newFP: currentFingerprint,
        jti: decoded.jti ? decoded.jti.slice(0, 8) + '…' : null,
      });
      emitSecurityEvent(decoded.sub, 'session:hijack', {
        reason: ipMismatch ? 'Fingerprint + IP mismatch (HIGH)' : 'Fingerprint mismatch (MEDIUM)',
        oldIP: decoded.ip,
        newIP: currentIP,
        jti: decoded.jti ? decoded.jti.slice(0, 8) + '…' : null,
      });
      return res.status(401).json({ success: false, message: 'SESSION_HIJACKED', code: 'HIJACK-401' });
    }

    // 3. Context tracking (IP / UA changes)
    if (ipMismatch || uaMismatch) {
      if (decoded.jti) {
        await store.recordSessionContextChange(decoded.jti, decoded.email, {
          ipMismatch,
          uaMismatch,
          oldIP: decoded.ip,
          newIP: currentIP,
          oldUA: decoded.ua,
          newUA: currentUA,
        });
      }
      if (ipMismatch) {
        await store.logAnomaly(decoded.email, 'IP_CHANGE', {
          reason: 'IP changed but fingerprint matches (LOW)',
          oldIP: decoded.ip,
          newIP: currentIP,
        });
      }
      if (uaMismatch) {
        await store.logAnomaly(decoded.email, 'UA_CHANGE', {
          reason: 'User-Agent changed but fingerprint matches (LOW)',
          oldUA: decoded.ua,
          newUA: currentUA,
        });
      }
    }

    // Valid active session — touch lastSeen
    if (decoded.jti) {
      await store.touchSession(decoded.jti);
    }

    req.user = decoded;
    req.sessionRecord = sessionRec;
    next();
  } catch (err) {
    req.authError = err.message;
    next(); // Let routes handle auth errors
  }
});

// ── Request logger ────────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/auth', authRoutes);

// ── Health check (includes DB & Redis status) ─────────────────────────────────
app.get('/health', async (_req, res) => {
  const dbHealthy = await checkDbHealth();
  const redisHealthy = await checkRedisHealth();
  const status = dbHealthy && redisHealthy ? 'ok' : 'degraded';

  res.json({
    status,
    service: 'VaultBase Auth API',
    time: new Date().toISOString(),
    postgres: dbHealthy ? 'connected' : 'unavailable',
    redis: redisHealthy ? 'connected' : 'unavailable',
  });
});

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// ── Global error handler ─────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ success: false, message: err.message || 'Internal server error' });
});

// ── Startup Sequence ─────────────────────────────────────────────────────────
async function startup() {
  try {
    // 1. Initialize PostgreSQL schema
    console.log('[Startup] Initializing PostgreSQL schema...');
    await initSchema();
    const dbOk = await checkDbHealth();
    console.log(`[Startup] PostgreSQL: ${dbOk ? '✅ connected' : '❌ unavailable'}`);

    // 2. Initialize Redis
    console.log('[Startup] Connecting to Redis...');
    getRedisClient();
    const redisOk = await checkRedisHealth();
    console.log(`[Startup] Redis: ${redisOk ? '✅ connected' : '❌ unavailable'}`);

    // 3. Fail-closed in production
    if (process.env.NODE_ENV === 'production') {
      if (!dbOk) {
        console.error('[FATAL] PostgreSQL unavailable in production — refusing to start');
        process.exit(1);
      }
      if (!redisOk) {
        console.error('[FATAL] Redis unavailable in production — refusing to start');
        process.exit(1);
      }
    }

    // 4. Seed demo users
    console.log('[Startup] Seeding demo users...');
    await store.seedUsers();

    // 5. Start HTTP server
    server.listen(PORT, () => {
      console.log(`\n✅  VaultBase Auth API running on http://localhost:${PORT}`);
      console.log(`   POST /auth/login`);
      console.log(`   POST /auth/send-otp`);
      console.log(`   POST /auth/verify-otp`);
      console.log(`   POST /auth/verify-face`);
      console.log(`   POST /auth/webauthn-register-options   (Phase 7: WebAuthn registration challenge)`);
      console.log(`   POST /auth/webauthn-register-verify    (Phase 7: WebAuthn registration verification)`);
      console.log(`   POST /auth/webauthn-auth-options       (Phase 7: WebAuthn auth challenge)`);
      console.log(`   POST /auth/webauthn-verify             (Phase 7: WebAuthn assertion verification)`);
      console.log(`   POST /auth/webauthn-challenge          (legacy alias → webauthn-auth-options)`);
      console.log(`   POST /auth/verify-fingerprint          (legacy alias → webauthn-verify)`);
      console.log(`   POST /auth/issue-tokens`);
      console.log(`   GET  /auth/overview                    (Phase 9: Security Overview)`);
      console.log(`   GET  /auth/audit-logs                  (Phase 9: Audit Logs)`);
      console.log(`   GET  /auth/risk-events                 (Phase 9: Risk Events)`);
      console.log(`   GET  /health                           (Phase 10: Health Check)`);
      console.log(`\n   Demo site → http://localhost:8080\n`);
    });
  } catch (err) {
    console.error('[FATAL] Startup failed:', err.message);
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
    // In development, attempt to start anyway for easier debugging
    server.listen(PORT, () => {
      console.log(`\n⚠️  VaultBase Auth API started in DEGRADED mode on http://localhost:${PORT}`);
    });
  }
}

startup();

module.exports = { app, server, io, emitSecurityEvent };
