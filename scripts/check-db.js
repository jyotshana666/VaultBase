'use strict';
const { Pool } = require('../backend/node_modules/pg');
const pool = new Pool({ host: '127.0.0.1', port: 5432, user: 'postgres', database: 'postgres' });

async function main() {
  const dbs = await pool.query("SELECT datname FROM pg_database WHERE datname IN ('vaultbase','vaultbase_test')");
  console.log('Databases:', dbs.rows);
  const roles = await pool.query("SELECT rolname FROM pg_roles WHERE rolname IN ('vaultbase_admin','postgres')");
  console.log('Roles:', roles.rows);
  await pool.end();
}
main().catch(e => { console.error(e.message); process.exit(1); });
