'use strict';

const { query } = require('./pool');
const { findUserByEmail } = require('./users');
const { v4: uuidv4 } = require('uuid');

async function getDevice(email, fingerprint) {
  if (!email || !fingerprint || fingerprint === 'unknown') return null;
  const emailLower = email.toLowerCase().trim();
  const res = await query(
    `SELECT d.id, d.user_id AS "userId", u.email, d.device_id AS "deviceId", d.device_name AS "deviceName",
            d.fingerprint, d.is_trusted AS "isTrusted", d.is_revoked AS "isRevoked",
            d.registered_at AS "registeredAt", d.last_used_at AS "lastUsedAt",
            d.last_ip AS "lastIP", d.revoked_at AS "revokedAt"
     FROM trusted_devices d
     JOIN users u ON d.user_id = u.id
     WHERE LOWER(u.email) = $1 AND d.fingerprint = $2`,
    [emailLower, fingerprint]
  );
  return res.rows[0] || null;
}

async function getDeviceStatus(email, fingerprint) {
  if (!fingerprint || fingerprint === 'unknown') return 'NEW';
  const dev = await getDevice(email, fingerprint);
  if (!dev) return 'NEW';
  if (dev.isRevoked) return 'REVOKED';
  if (dev.isTrusted) return 'TRUSTED';
  return 'NEW';
}

async function getUserDevices(email) {
  if (!email) return [];
  const emailLower = email.toLowerCase().trim();
  const res = await query(
    `SELECT d.id, d.fingerprint, d.device_name AS "deviceName",
            d.is_trusted AS "isTrusted", d.is_revoked AS "isRevoked",
            CASE
              WHEN d.is_revoked THEN 'REVOKED'
              WHEN d.is_trusted THEN 'TRUSTED'
              ELSE 'NEW'
            END AS status,
            d.registered_at AS "registeredAt",
            d.last_used_at AS "lastSeenAt",
            d.last_ip AS "lastIP",
            d.revoked_at AS "revokedAt"
     FROM trusted_devices d
     JOIN users u ON d.user_id = u.id
     WHERE LOWER(u.email) = $1
     ORDER BY d.registered_at DESC`,
    [emailLower]
  );
  return res.rows;
}

async function registerDevice(email, fingerprint, deviceName = 'Chrome Browser', ip = '127.0.0.1') {
  if (!email || !fingerprint || fingerprint === 'unknown') return null;
  const emailLower = email.toLowerCase().trim();
  const user = await findUserByEmail(emailLower);
  if (!user) return null;

  const existing = await getDevice(emailLower, fingerprint);
  if (existing) {
    if (!existing.isRevoked) {
      await query(
        `UPDATE trusted_devices
         SET is_trusted = true, last_used_at = CURRENT_TIMESTAMP, last_ip = $1
         WHERE id = $2`,
        [ip, existing.id]
      );
      existing.isTrusted = true;
      existing.lastIP = ip;
      existing.lastUsedAt = new Date().toISOString();
    }
    return existing;
  }

  const deviceId = uuidv4();
  const res = await query(
    `INSERT INTO trusted_devices (id, user_id, device_id, device_name, fingerprint, is_trusted, is_revoked, registered_at, last_used_at, last_ip)
     VALUES ($1, $2, $3, $4, $5, true, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $6)
     RETURNING id, user_id AS "userId", device_id AS "deviceId", device_name AS "deviceName",
               fingerprint, is_trusted AS "isTrusted", is_revoked AS "isRevoked",
               registered_at AS "registeredAt", last_used_at AS "lastUsedAt", last_ip AS "lastIP"`,
    [uuidv4(), user.id, deviceId, deviceName || 'Chrome Browser', fingerprint, ip]
  );
  return res.rows[0];
}

async function revokeDevice(email, fingerprintOrId) {
  if (!email || !fingerprintOrId) return false;
  const emailLower = email.toLowerCase().trim();
  const res = await query(
    `UPDATE trusted_devices d
     SET is_trusted = false, is_revoked = true, revoked_at = CURRENT_TIMESTAMP
     FROM users u
     WHERE d.user_id = u.id
       AND LOWER(u.email) = $1
       AND (d.fingerprint = $2 OR d.id::text = $2 OR d.device_id = $2)
     RETURNING d.id, d.fingerprint, d.user_id AS "userId"`,
    [emailLower, fingerprintOrId]
  );
  return (res.rowCount || 0) > 0;
}

module.exports = {
  getDevice,
  getDeviceStatus,
  getUserDevices,
  registerDevice,
  revokeDevice,
};
