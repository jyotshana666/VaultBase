'use strict';

const { query } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function findUserByEmail(email) {
  if (!email) return null;
  const emailLower = email.toLowerCase().trim();
  const res = await query(
    'SELECT id, email, password_hash AS "passwordHash", face_registered AS "faceRegistered", face_descriptor AS "faceDescriptor", created_at AS "createdAt", updated_at AS "updatedAt" FROM users WHERE LOWER(email) = $1',
    [emailLower]
  );
  return res.rows[0] || null;
}

async function findUserById(id) {
  if (!id) return null;
  const res = await query(
    'SELECT id, email, password_hash AS "passwordHash", face_registered AS "faceRegistered", face_descriptor AS "faceDescriptor", created_at AS "createdAt", updated_at AS "updatedAt" FROM users WHERE id = $1',
    [id]
  );
  return res.rows[0] || null;
}

async function createUser({ id, email, passwordHash, faceDescriptor = null }) {
  const userId = id || uuidv4();
  const emailLower = email.toLowerCase().trim();
  const faceRegistered = faceDescriptor !== null && Array.isArray(faceDescriptor);

  const res = await query(
    `INSERT INTO users (id, email, password_hash, face_registered, face_descriptor, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
     RETURNING id, email, password_hash AS "passwordHash", face_registered AS "faceRegistered", face_descriptor AS "faceDescriptor", created_at AS "createdAt", updated_at AS "updatedAt"`,
    [userId, emailLower, passwordHash, faceRegistered, faceDescriptor ? JSON.stringify(faceDescriptor) : null]
  );
  return res.rows[0];
}

async function updateFaceDescriptor(userId, faceDescriptor) {
  if (!userId || !faceDescriptor) return false;
  const res = await query(
    `UPDATE users
     SET face_descriptor = $1, face_registered = true, updated_at = CURRENT_TIMESTAMP
     WHERE id = $2
     RETURNING id`,
    [JSON.stringify(faceDescriptor), userId]
  );
  return (res.rowCount || 0) > 0;
}

async function listUsers() {
  const res = await query(
    'SELECT id, email, password_hash AS "passwordHash", face_registered AS "faceRegistered", face_descriptor AS "faceDescriptor", created_at AS "createdAt" FROM users ORDER BY created_at ASC'
  );
  return res.rows;
}

module.exports = {
  findUserByEmail,
  findUserById,
  createUser,
  updateFaceDescriptor,
  listUsers,
};
