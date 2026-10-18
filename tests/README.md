# VaultBase Test Suite

This directory is designated for integration and automated end-to-end tests across the VaultBase components.

## Test Suites

### 1. Comprehensive Authentication, OTP, Risk Engine, Device Trust & Face Biometric Test Suite (`tests/auth-flow.test.js`)
Runs the complete multi-factor authentication sequence, Secure OTP, Phase 4 Risk Engine, Phase 5 Device Trust, and Phase 6 Face Biometric tests:
- Health check (`GET /health`)
- User registration with bcrypt hashing (`POST /auth/register`)
- Credential validation and rejection of invalid passwords (`POST /auth/login`)
- Dynamic CSPRNG 6-digit OTP generation (cryptographic entropy)
- Nonce/HMAC-SHA256 hashed OTP storage with timing-safe verification (`crypto.timingSafeEqual`)
- Zero exposure of OTP in API responses and console logs
- Resend rate-limiting (30s cooldown with HTTP 429 response)
- Old OTP invalidation upon resend
- Attempt protection and lockout (invalidates challenge after 3 failed attempts)
- Reused / replayed OTP rejection (immediate one-time consumption)
- Expired OTP rejection (5-minute TTL)
- Device Trust: Initial registration establishes first TRUSTED device
- Device Trust: Isolated user device namespaces (User A trusted device is NEW for User B)
- Device Trust: Authoritative server-side device evaluation (client `trusted: true` / `isNewDevice: false` spoofing rejected)
- Device Trust: Automatic promotion to TRUSTED upon successful full authentication completion
- Device Management: Device listing (`GET /auth/devices`) and revocation (`POST /auth/devices/revoke`)
- Device Trust: Revoked device triggers elevated risk (`REVOKED_DEVICE` +40) and forces step-up authentication
- Risk Engine: Low-risk single-factor evaluation (`["otp"]`)
- Risk Engine: Medium-risk two-factor evaluation (`["otp", "device"]`)
- Risk Engine: High & Critical three-factor evaluation (`["otp", "face", "device"]`)
- Risk Signals: Individual and cumulative weights (Revoked Device +40, New Device +30, Failed Attempts +25, IP Change +20, Unusual Hour +15)
- Security: Client payload tampering protection (spoofed riskScore/riskLevel/requiredFactors/deviceTrust ignored)
- Security: Incomplete factor token rejection (HTTP 403)
- Structured Risk & Device Audit Trail (`store.riskAuditLogs`, `store.anomalyLogs`)
- **Face Biometrics (Phase 6):**
  - `livenessVerified: true` flag without descriptor rejected (400) — synthetic bypass removed
  - Null/missing descriptor rejected (400)
  - All-zero descriptor rejected via statistical variance check (400)
  - Constant-value descriptor rejected via variance check (400)
  - Wrong-length (64-element) descriptor rejected (400)
  - Non-numeric element descriptor rejected (400)
  - Face enrollment with valid 128D descriptor (enrolled = true)
  - Face descriptor stored as 128-element float array on user record
  - Random/impostor descriptor fails Euclidean distance check (401)
  - Cross-user descriptor fails distance check (401)
  - `FACE_VERIFICATION_MISMATCH` and `INVALID_FACE_DESCRIPTOR` anomaly events logged
  - Valid matching descriptor (±1% perturbation) accepted within threshold 0.50 (200)
  - Factor enforcement: token issuance blocked without face factor (403)
- Biometric face verification (`POST /auth/verify-face`)
- Device recognition (`POST /auth/verify-device`)
- Token issuance and JWT claim verification (`POST /auth/issue-tokens`)

**Run command:**
```bash
node tests/auth-flow.test.js
```

2. **Integration & Security Tests**:
   - Cross-Origin Resource Sharing (CORS) enforcement across authorized origins.
   - JWT validation, expiration, and invalidation.
   - Brute-force and rate-limit simulation.

3. **Extension E2E (Puppeteer / Playwright)**:
   - Extension injection of "Sign in with VaultBase" button into `demo-bank`.
   - Mocked WebCam stream biometric verification flow.
