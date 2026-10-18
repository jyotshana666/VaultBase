'use strict';

const { query } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function createSession({ jti, userId, email, deviceFp, ip, userAgent, accessTtlMs = 3600 * 1000 }) {
  const id = uuidv4();
  const issuedAtMs = Date.now();
  const expiresAtMs = issuedAtMs + accessTtlMs;
  const issuedAt = new Date(issuedAtMs);
  const expiresAt = new Date(expiresAtMs);

  const res = await query(
    `INSERT INTO sessions (id, jti, user_id, email, device_fingerprint, ip_address, user_agent, status, context_changes, issued_at, expires_at, last_seen_at, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', 0, $8, $9, $8, CURRENT_TIMESTAMP)
     RETURNING id, jti, user_id AS "userId", email, device_fingerprint AS "deviceFp",
               ip_address AS "ip", user_agent AS "userAgent", status,
               revoke_reason AS "revokeReason", revoked_at AS "revokedAt",
               context_changes AS "contextChanges",
               EXTRACT(EPOCH FROM issued_at) * 1000 AS "issuedAt",
               EXTRACT(EPOCH FROM expires_at) * 1000 AS "expiresAt",
               EXTRACT(EPOCH FROM last_seen_at) * 1000 AS "lastSeenAt"`,
    [id, jti, userId, (email || '').toLowerCase().trim(), deviceFp || null, ip || null, (userAgent || '').slice(0, 256), issuedAt, expiresAt]
  );

  const row = res.rows[0];
  if (row) {
    row.issuedAt = Number(row.issuedAt);
    row.expiresAt = Number(row.expiresAt);
    row.lastSeenAt = Number(row.lastSeenAt);
  }
  return row;
}

async function getSessionByJti(jti) {
  if (!jti) return null;
  const res = await query(
    `SELECT id, jti, user_id AS "userId", email, device_fingerprint AS "deviceFp",
            ip_address AS "ip", user_agent AS "userAgent", status,
            revoke_reason AS "revokeReason", revoked_at AS "revokedAt",
            context_changes AS "contextChanges",
            EXTRACT(EPOCH FROM issued_at) * 1000 AS "issuedAt",
            EXTRACT(EPOCH FROM expires_at) * 1000 AS "expiresAt",
            EXTRACT(EPOCH FROM last_seen_at) * 1000 AS "lastSeenAt"
     FROM sessions
     WHERE jti = $1`,
    [jti]
  );

  const row = res.rows[0];
  if (!row) return null;
  row.issuedAt = Number(row.issuedAt);
  row.expiresAt = Number(row.expiresAt);
  row.lastSeenAt = Number(row.lastSeenAt);

  // Lazy expiration
  if (row.status === 'active' && Date.now() > row.expiresAt) {
    row.status = 'expired';
    await query("UPDATE sessions SET status = 'expired' WHERE jti = $1", [jti]);
  }

  return row;
}

async function getUserSessions(userId) {
  if (!userId) return [];
  const res = await query(
    `SELECT id, jti, user_id AS "userId", email, device_fingerprint AS "deviceFp",
            ip_address AS "ip", user_agent AS "userAgent", status,
            revoke_reason AS "revokeReason", revoked_at AS "revokedAt",
            context_changes AS "contextChanges",
            EXTRACT(EPOCH FROM issued_at) * 1000 AS "issuedAt",
            EXTRACT(EPOCH FROM expires_at) * 1000 AS "expiresAt",
            EXTRACT(EPOCH FROM last_seen_at) * 1000 AS "lastSeenAt"
     FROM sessions
     WHERE user_id = $1
     ORDER BY issued_at DESC`,
    [userId]
  );

  return res.rows.map((row) => {
    const r = {
      ...row,
      issuedAt: Number(row.issuedAt),
      expiresAt: Number(row.expiresAt),
      lastSeenAt: Number(row.lastSeenAt),
    };
    if (r.status === 'active' && Date.now() > r.expiresAt) {
      r.status = 'expired';
    }
    return r;
  });
}

async function revokeSession(jti, reason = 'admin') {
  if (!jti) return false;
  const res = await query(
    `UPDATE sessions
     SET status = 'revoked', revoke_reason = $1, revoked_at = CURRENT_TIMESTAMP
     WHERE jti = $2
     RETURNING id, jti, user_id AS "userId", email, ip_address AS "ip"`,
    [reason, jti]
  );
  return (res.rowCount || 0) > 0;
}

async function revokeAllUserSessions(userId, reason = 'revoke-all') {
  if (!userId) return 0;
  const res = await query(
    `UPDATE sessions
     SET status = 'revoked', revoke_reason = $1, revoked_at = CURRENT_TIMESTAMP
     WHERE user_id = $2 AND status = 'active'
     RETURNING id, jti`,
    [reason, userId]
  );
  return res.rowCount || 0;
}

async function recordContextChange(jti, details) {
  if (!jti) return null;
  const res = await query(
    `UPDATE sessions
     SET context_changes = context_changes + 1, last_seen_at = CURRENT_TIMESTAMP
     WHERE jti = $1
     RETURNING id, jti, user_id AS "userId", email, context_changes AS "contextChanges"`,
    [jti]
  );
  return res.rows[0] || null;
}

async function touchSession(jti) {
  if (!jti) return false;
  const res = await query(
    `UPDATE sessions
     SET last_seen_at = CURRENT_TIMESTAMP
     WHERE jti = $1 AND status = 'active'`,
    [jti]
  );
  return (res.rowCount || 0) > 0;
}

module.exports = {
  createSession,
  getSessionByJti,
  getUserSessions,
  revokeSession,
  revokeAllUserSessions,
  recordContextChange,
  touchSession,
};
