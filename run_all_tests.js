const { execSync } = require('child_process');

console.log('Running test suite for Phase 10...\n');

const tests = [
  'persistence.test.js',
  'auth-flow.test.js',
  'webauthn.test.js',
  'session-security.test.js',
  'dashboard.test.js'
];

let totalPassed = 0;
let totalFailed = 0;

for (const file of tests) {
  console.log(`=== Running ${file} ===`);
  try {
    const output = execSync(`node tests/${file}`, { 
      env: { ...process.env, NODE_ENV: 'test', POSTGRES_PORT: '5432' },
      stdio: 'pipe' 
    });
    console.log(output.toString());
    console.log(`[Result] ${file}: 1 passed / 0 failed (Assuming success based on exit code 0)`);
    totalPassed++;
  } catch (err) {
    console.error(err.stdout ? err.stdout.toString() : '');
    console.error(err.stderr ? err.stderr.toString() : '');
    console.log(`[Result] ${file}: 0 passed / 1 failed`);
    totalFailed++;
  }
  console.log('\n');
}

console.log(`=== FINAL SUMMARY ===`);
console.log(`TOTAL: ${totalPassed} passed / ${totalFailed} failed`);
