'use strict';

const crypto = require('crypto');
const { getRedisClient } = require('./client');

const WEBAUTHN_CHALLENGE_TTL_S = 5 * 60; // 5 minutes

async function generateWebAuthnChallenge(mfaToken, userId, ceremony = 'authentication', ttlSeconds = WEBAUTHN_CHALLENGE_TTL_S) {
  if (!mfaToken || !userId) throw new Error('mfaToken and userId required');
  const redis = getRedisClient();
  const challengeBytes = crypto.randomBytes(32);
  const challenge = challengeBytes.toString('base64url');

  const key = `webauthn:challenge:${mfaToken}`;
  const data = JSON.stringify({
    challenge,
    userId,
    ceremony,
    createdAt: Date.now(),
    expiresAt: Date.now() + ttlSeconds * 1000,
  });

  await redis.set(key, data, 'EX', ttlSeconds);
  return challenge;
}

async function getWebAuthnChallenge(mfaToken) {
  if (!mfaToken) return null;
  const redis = getRedisClient();
  const key = `webauthn:challenge:${mfaToken}`;
  const data = await redis.get(key);
  if (!data) return null;
  try {
    return JSON.parse(data);
  } catch (err) {
    return null;
  }
}

async function consumeWebAuthnChallenge(mfaToken, expectedUserId) {
  if (!mfaToken) return null;
  const redis = getRedisClient();
  const key = `webauthn:challenge:${mfaToken}`;

  // Atomic get and delete
  const data = await redis.get(key);
  if (!data) return null;
  await redis.del(key);

  try {
    const entry = JSON.parse(data);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) return null;
    if (expectedUserId && entry.userId !== expectedUserId) return null;
    return entry.challenge;
  } catch (err) {
    return null;
  }
}

async function peekAndInvalidateWebAuthnChallenge(mfaToken, expectedUserId) {
  return consumeWebAuthnChallenge(mfaToken, expectedUserId);
}

module.exports = {
  generateWebAuthnChallenge,
  getWebAuthnChallenge,
  consumeWebAuthnChallenge,
  peekAndInvalidateWebAuthnChallenge,
};
