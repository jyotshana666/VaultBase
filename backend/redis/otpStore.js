'use strict';

const { getRedisClient } = require('./client');

const OTP_TTL_S = 5 * 60; // 5 minutes
const OTP_COOLDOWN_S = 30; // 30 seconds

async function storeOtpChallenge(mfaToken, { hashedOtp, userId, email }, ttlSeconds = OTP_TTL_S) {
  if (!mfaToken || !hashedOtp) return false;
  const redis = getRedisClient();
  const key = `otp:challenge:${mfaToken}`;
  const data = JSON.stringify({
    hashedOtp,
    userId,
    email: (email || '').toLowerCase().trim(),
    attempts: 0,
    maxAttempts: 3,
    createdAt: Date.now(),
    expiresAt: Date.now() + ttlSeconds * 1000,
  });

  await redis.set(key, data, 'EX', ttlSeconds);
  return true;
}

async function getOtpChallenge(mfaToken) {
  if (!mfaToken) return null;
  const redis = getRedisClient();
  const key = `otp:challenge:${mfaToken}`;
  const data = await redis.get(key);
  if (!data) return null;
  try {
    return JSON.parse(data);
  } catch (err) {
    return null;
  }
}

async function incrementOtpAttempts(mfaToken) {
  if (!mfaToken) return 0;
  const redis = getRedisClient();
  const key = `otp:challenge:${mfaToken}`;
  const challenge = await getOtpChallenge(mfaToken);
  if (!challenge) return 0;

  challenge.attempts = (challenge.attempts || 0) + 1;
  const ttl = await redis.ttl(key);
  if (ttl > 0) {
    await redis.set(key, JSON.stringify(challenge), 'EX', ttl);
  }
  return challenge.attempts;
}

async function consumeOtpChallenge(mfaToken) {
  if (!mfaToken) return null;
  const redis = getRedisClient();
  const key = `otp:challenge:${mfaToken}`;
  const challenge = await getOtpChallenge(mfaToken);
  if (!challenge) return null;
  await redis.del(key);
  return challenge;
}

async function setOtpCooldown(mfaToken, cooldownSeconds = OTP_COOLDOWN_S) {
  if (!mfaToken) return false;
  const redis = getRedisClient();
  const key = `otp:cooldown:${mfaToken}`;
  await redis.set(key, '1', 'EX', cooldownSeconds);
  return true;
}

async function isOtpInCooldown(mfaToken) {
  if (!mfaToken) return false;
  const redis = getRedisClient();
  const key = `otp:cooldown:${mfaToken}`;
  const val = await redis.get(key);
  return val !== null;
}

async function deleteOtpChallenge(mfaToken) {
  if (!mfaToken) return false;
  const redis = getRedisClient();
  await redis.del(`otp:challenge:${mfaToken}`);
  await redis.del(`otp:cooldown:${mfaToken}`);
  return true;
}

module.exports = {
  storeOtpChallenge,
  getOtpChallenge,
  incrementOtpAttempts,
  consumeOtpChallenge,
  setOtpCooldown,
  isOtpInCooldown,
  deleteOtpChallenge,
};
