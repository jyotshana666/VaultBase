'use strict';

const { getRedisClient } = require('./client');

const MFA_SESSION_TTL_S = 15 * 60; // 15 minutes

/**
 * Create a new MFA in-flight session in Redis.
 * @param {string} mfaToken  – unique session identifier
 * @param {object} sessionData – full session payload
 * @param {number} [ttlSeconds] – time-to-live (default 15 min)
 */
async function createMfaSession(mfaToken, sessionData, ttlSeconds = MFA_SESSION_TTL_S) {
  if (!mfaToken) return false;
  const redis = getRedisClient();
  const key = `mfa:session:${mfaToken}`;
  const data = JSON.stringify(sessionData);
  await redis.set(key, data, 'EX', ttlSeconds);
  return true;
}

/**
 * Retrieve an MFA session by token. Returns null if expired or not found.
 */
async function getMfaSession(mfaToken) {
  if (!mfaToken) return null;
  const redis = getRedisClient();
  const key = `mfa:session:${mfaToken}`;
  const data = await redis.get(key);
  if (!data) return null;
  try {
    return JSON.parse(data);
  } catch (err) {
    return null;
  }
}

/**
 * Update specific fields on an existing MFA session.
 * Preserves the remaining TTL.
 */
async function updateMfaSession(mfaToken, updates) {
  if (!mfaToken) return false;
  const redis = getRedisClient();
  const key = `mfa:session:${mfaToken}`;

  const existing = await getMfaSession(mfaToken);
  if (!existing) return false;

  const merged = { ...existing, ...updates };
  const ttl = await redis.ttl(key);
  if (ttl > 0) {
    await redis.set(key, JSON.stringify(merged), 'EX', ttl);
  } else {
    // Key has no expiry or is about to expire — re-set with default TTL
    await redis.set(key, JSON.stringify(merged), 'EX', MFA_SESSION_TTL_S);
  }
  return true;
}

/**
 * Delete an MFA session (consumed after token issuance or expired).
 */
async function deleteMfaSession(mfaToken) {
  if (!mfaToken) return false;
  const redis = getRedisClient();
  const key = `mfa:session:${mfaToken}`;
  await redis.del(key);
  return true;
}

module.exports = {
  createMfaSession,
  getMfaSession,
  updateMfaSession,
  deleteMfaSession,
};
