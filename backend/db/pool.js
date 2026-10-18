'use strict';

require('dotenv').config();
const { Pool } = require('pg');

let pool = null;

function getPoolConfig() {
  if (process.env.DATABASE_URL) {
    return {
      connectionString: process.env.DATABASE_URL,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    };
  }

  const host = process.env.POSTGRES_HOST || '127.0.0.1';
  const port = parseInt(process.env.POSTGRES_PORT || '5433', 10);
  const user = process.env.POSTGRES_USER || 'vaultbase_admin';
  const password = process.env.POSTGRES_PASSWORD !== undefined ? process.env.POSTGRES_PASSWORD : 'vaultbase_secret';
  const database = process.env.POSTGRES_DB || 'vaultbase';

  return {
    host,
    port,
    user,
    password,
    database,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  };
}

function getPool() {
  if (!pool) {
    const config = getPoolConfig();
    pool = new Pool(config);

    pool.on('error', (err) => {
      console.error('[DB] Unexpected PostgreSQL pool client error:', err.message);
    });
  }
  return pool;
}

async function query(text, params) {
  const p = getPool();
  const start = Date.now();
  try {
    const res = await p.query(text, params);
    return res;
  } catch (err) {
    console.error(`[DB Error] Query failed: ${err.message}`);
    throw err;
  }
}

async function withTransaction(callback) {
  const p = getPool();
  const client = await p.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function checkHealth() {
  try {
    const res = await query('SELECT 1 as healthy');
    return res.rows[0]?.healthy === 1;
  } catch (err) {
    return false;
  }
}

async function closePool() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

module.exports = {
  getPool,
  query,
  withTransaction,
  checkHealth,
  closePool,
};
