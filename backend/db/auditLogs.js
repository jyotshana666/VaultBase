'use strict';

const { query } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function logAuditEvent({ userId, email, eventType, status = 'SUCCESS', ipAddress, details }) {
  const id = uuidv4();
  const emailLower = email ? email.toLowerCase().trim() : null;

  const res = await query(
    `INSERT INTO audit_logs (id, user_id, email, event_type, status, ip_address, details, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
     RETURNING id, user_id AS "userId", email, event_type AS "eventType", status,
               ip_address AS "ipAddress", details, created_at AS "createdAt"`,
    [id, userId || null, emailLower, eventType, status, ipAddress || null, details ? JSON.stringify(details) : null]
  );
  return res.rows[0];
}

async function getUserAuditLogs(emailOrUserId, limit = 50) {
  if (!emailOrUserId) return [];
  const queryStr = `
    SELECT id, user_id AS "userId", email, event_type AS "eventType",
           status, ip_address AS "ipAddress", details, created_at AS "createdAt"
    FROM audit_logs
    WHERE user_id::text = $1 OR LOWER(email) = LOWER($1)
    ORDER BY created_at DESC
    LIMIT $2
  `;
  const res = await query(queryStr, [emailOrUserId.toString().trim(), limit]);
  return res.rows;
}

module.exports = {
  logAuditEvent,
  getUserAuditLogs,
};
