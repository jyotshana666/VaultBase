'use strict';

const { query } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function logRiskEvent({ userId, email, eventType, riskScore, riskLevel, signals, details, ipAddress }) {
  const id = uuidv4();
  const emailLower = email ? email.toLowerCase().trim() : null;

  const res = await query(
    `INSERT INTO risk_events (id, user_id, email, event_type, risk_score, risk_level, signals, details, ip_address, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
     RETURNING id, user_id AS "userId", email, event_type AS "eventType",
               risk_score AS "riskScore", risk_level AS "riskLevel",
               signals, details, ip_address AS "ipAddress", created_at AS "createdAt"`,
    [
      id,
      userId || null,
      emailLower,
      eventType,
      riskScore !== undefined ? riskScore : null,
      riskLevel || null,
      signals ? JSON.stringify(signals) : null,
      details ? JSON.stringify(details) : null,
      ipAddress || null,
    ]
  );
  return res.rows[0];
}

async function getUserRiskEvents(emailOrUserId, limit = 50) {
  if (!emailOrUserId) return [];
  const queryStr = `
    SELECT id, user_id AS "userId", email, event_type AS "eventType",
           risk_score AS "riskScore", risk_level AS "riskLevel",
           signals, details, ip_address AS "ipAddress", created_at AS "createdAt"
    FROM risk_events
    WHERE user_id::text = $1 OR LOWER(email) = LOWER($1)
    ORDER BY created_at DESC
    LIMIT $2
  `;
  const res = await query(queryStr, [emailOrUserId.toString().trim(), limit]);
  return res.rows;
}

module.exports = {
  logRiskEvent,
  getUserRiskEvents,
};
