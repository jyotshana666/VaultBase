'use strict';

const fs = require('fs');
const path = require('path');
const { query } = require('./pool');

async function initSchema() {
  const schemaPath = path.join(__dirname, '../../database/schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await query(sql);
  console.log('[DB] Database schema initialized successfully');
}

module.exports = { initSchema };

if (require.main === module) {
  initSchema()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[DB Init Failed]', err);
      process.exit(1);
    });
}
