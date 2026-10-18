'use strict';

const { getRedisClient } = require('./client');

// ── Revoked JTI Cache ─────────────────────────────────────────────────────────

/**
 * Cache a revoked JTI in Redis for distributed revocation across processes.
 * TTL should match the original token's remaining lifetime.
 * @param {string} jti – the JWT ID to mark as revoked
 * @param {number} ttlSeconds – time-to-live for the revocation entry
 */
async function cacheRevokedJti(jti, ttlSeconds = 3600) {
  if (!jti) return false;
  const redis = getRedisClient();
  const key = `session:revoked:${jti}`;
  await redis.set(key, '1', 'EX', ttlSeconds);
  return true;
}

/**
 * Check whether a JTI has been revoked in the distributed cache.
 * This is the fast-path check before falling through to PostgreSQL.
 */
async function isJtiRevoked(jti) {
  if (!jti) return false;
  const redis = getRedisClient();
  const key = `session:revoked:${jti}`;
  const val = await redis.get(key);
  return val !== null;
}

// ── Active Session Cache ──────────────────────────────────────────────────────

/**
 * Cache active session metadata for low-latency lookups.
 * @param {string} jti
 * @param {object} sessionData
 * @param {number} [ttlSeconds]
 */
async function cacheActiveSession(jti, sessionData, ttlSeconds = 3600) {
  if (!jti) return false;
  const redis = getRedisClient();
  const key = `session:active:${jti}`;
  await redis.set(key, JSON.stringify(sessionData), 'EX', ttlSeconds);
  return true;
}

/**
 * Get cached active session. Returns null if not cached.
 */
async function getActiveSession(jti) {
  if (!jti) return null;
  const redis = getRedisClient();
  const key = `session:active:${jti}`;
  const data = await redis.get(key);
  if (!data) return null;
  try {
    return JSON.parse(data);
  } catch (err) {
    return null;
  }
}

/**
 * Remove an active session from cache (on revoke or expire).
 */
async function removeActiveSession(jti) {
  if (!jti) return false;
  const redis = getRedisClient();
  const key = `session:active:${jti}`;
  await redis.del(key);
  return true;
}

module.exports = {
  cacheRevokedJti,
  isJtiRevoked,
  cacheActiveSession,
  getActiveSession,
  removeActiveSession,
};
