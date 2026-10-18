'use strict';

const { query } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function createSecurityAlert({ userId, email, alertType, severity = 'WARNING', title, description, metadata }) {
  const id = uuidv4();
  const emailLower = email ? email.toLowerCase().trim() : null;

  const res = await query(
    `INSERT INTO security_alerts (id, user_id, email, alert_type, severity, title, description, metadata, is_read, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, CURRENT_TIMESTAMP)
     RETURNING id, user_id AS "userId", email, alert_type AS "alertType",
               severity, title, description, metadata, is_read AS "isRead", created_at AS "createdAt"`,
    [id, userId || null, emailLower, alertType, severity, title, description || null, metadata ? JSON.stringify(metadata) : null]
  );
  return res.rows[0];
}

async function getUserAlerts(userId, limit = 50) {
  if (!userId) return [];
  const res = await query(
    `SELECT id, user_id AS "userId", email, alert_type AS "alertType",
            severity, title, description, metadata, is_read AS "isRead", created_at AS "createdAt"
     FROM security_alerts
     WHERE user_id = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [userId, limit]
  );
  return res.rows;
}

async function markAlertRead(alertId, userId) {
  if (!alertId || !userId) return false;
  const res = await query(
    `UPDATE security_alerts
     SET is_read = true
     WHERE id = $1 AND user_id = $2`,
    [alertId, userId]
  );
  return (res.rowCount || 0) > 0;
}

module.exports = {
  createSecurityAlert,
  getUserAlerts,
  markAlertRead,
};
