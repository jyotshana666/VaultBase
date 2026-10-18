'use strict';
/**
 * One-time test database setup script.
 * Creates role vaultbase_admin + database vaultbase on the local PostgreSQL instance.
 * Run as: node scripts/setup-test-db.js
 */
const { Pool } = require('../backend/node_modules/pg');

async function main() {
  // Connect as postgres superuser to create role + database
  const adminPool = new Pool({ host: '127.0.0.1', port: 5432, user: 'postgres', database: 'postgres' });

  try {
    // Create role if it doesn't exist
    await adminPool.query("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vaultbase_admin') THEN CREATE ROLE vaultbase_admin WITH LOGIN PASSWORD 'vaultbase_secret'; END IF; END $$;");
    console.log('✅ Role vaultbase_admin ready');

    // Create database if not exists (can't use IF NOT EXISTS in older PG, so check first)
    const dbCheck = await adminPool.query("SELECT 1 FROM pg_database WHERE datname = 'vaultbase'");
    if (dbCheck.rowCount === 0) {
      await adminPool.query('CREATE DATABASE vaultbase OWNER vaultbase_admin');
      console.log('✅ Database vaultbase created');
    } else {
      console.log('✅ Database vaultbase already exists');
    }

    // Grant privileges
    await adminPool.query('GRANT ALL PRIVILEGES ON DATABASE vaultbase TO vaultbase_admin');
    console.log('✅ Privileges granted to vaultbase_admin');

  } finally {
    await adminPool.end();
  }

  // Connect to vaultbase DB to grant schema privileges
  const vbPool = new Pool({ host: '127.0.0.1', port: 5432, user: 'postgres', database: 'vaultbase' });
  try {
    await vbPool.query('GRANT ALL ON SCHEMA public TO vaultbase_admin');
    console.log('✅ Schema public privileges granted');
  } finally {
    await vbPool.end();
  }

  console.log('\n✅ Test database setup complete. Use POSTGRES_PORT=5432 for tests.');
}

main().catch(e => { console.error('Setup failed:', e.message); process.exit(1); });
