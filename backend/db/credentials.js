'use strict';

const { query } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function saveCredential(userId, credInfo) {
  if (!userId || !credInfo || !credInfo.credentialId) {
    throw new Error('Invalid credential info');
  }

  const res = await query(
    `INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, transports, device_type, backed_up, created_at, last_used_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, NULL)
     RETURNING id, user_id AS "userId", credential_id AS "credentialId", public_key AS "publicKey",
               sign_count AS "signCount", transports, device_type AS "deviceType",
               backed_up AS "backedUp", created_at AS "createdAt", last_used_at AS "lastUsedAt"`,
    [
      uuidv4(),
      userId,
      credInfo.credentialId,
      credInfo.publicKey,
      credInfo.signCount ?? 0,
      credInfo.transports ?? [],
      credInfo.deviceType ?? 'unknown',
      credInfo.backedUp ?? false,
    ]
  );
  const row = res.rows[0];
  if (row) row.signCount = parseInt(row.signCount, 10);
  return row;
}

async function getCredential(userId, credentialId) {
  if (!userId || !credentialId) return null;
  const res = await query(
    `SELECT id, user_id AS "userId", credential_id AS "credentialId", public_key AS "publicKey",
            sign_count AS "signCount", transports, device_type AS "deviceType",
            backed_up AS "backedUp", created_at AS "createdAt", last_used_at AS "lastUsedAt"
     FROM webauthn_credentials
     WHERE user_id = $1 AND credential_id = $2`,
    [userId, credentialId]
  );
  if (!res.rows[0]) return null;
  const row = res.rows[0];
  row.signCount = parseInt(row.signCount, 10);
  return row;
}

async function getUserCredentials(userId) {
  if (!userId) return [];
  const res = await query(
    `SELECT id, user_id AS "userId", credential_id AS "credentialId", public_key AS "publicKey",
            sign_count AS "signCount", transports, device_type AS "deviceType",
            backed_up AS "backedUp", created_at AS "createdAt", last_used_at AS "lastUsedAt"
     FROM webauthn_credentials
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [userId]
  );
  return res.rows.map((r) => ({
    ...r,
    signCount: parseInt(r.signCount, 10),
  }));
}

async function updateCredentialSignCount(userId, credentialId, { newSignCount, backedUp }) {
  if (!userId || !credentialId) return false;
  const params = [newSignCount, userId, credentialId];
  let backedUpSql = '';
  if (backedUp !== undefined) {
    params.push(backedUp);
    backedUpSql = `, backed_up = $${params.length}`;
  }

  const res = await query(
    `UPDATE webauthn_credentials
     SET sign_count = $1, last_used_at = CURRENT_TIMESTAMP ${backedUpSql}
     WHERE user_id = $2 AND credential_id = $3`,
    params
  );
  return (res.rowCount || 0) > 0;
}

module.exports = {
  saveCredential,
  getCredential,
  getUserCredentials,
  updateCredentialSignCount,
};
