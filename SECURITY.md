# VaultBase Security Policy & Architecture

## Security Model Overview

VaultBase replaces traditional insecure password entry with a multi-layered verification model:

1. **Local Biometrics**: Face detection and recognition executed locally within the Chrome Extension client sandbox via TensorFlow.js (face-api.js). Biometric descriptors are 128D float arrays kept on-device and matched against authorized profiles with Euclidean distance threshold (0.5).

2. **Device Cryptographic Binding**: Unique device identifiers and challenge-response proofs establish device authenticity through WebAuthn/FIDO2 credentials.

3. **Out-of-Band Verification**: Time-sensitive 6-digit One-Time Passcodes (OTP) dispatched via secure communication channels (email).

4. **Session Integrity**: High-entropy JWT tokens with short lifespans (1 hour), strict origin scoping, and server-side validation via PostgreSQL + Redis.

---

## Security Controls Summary (Phase 13.1 - October 2026)

| Control | Implementation | Status |
|---------|----------------|--------|
| **Cookie Security** | `HttpOnly`, `SameSite=Strict` (dev) / `SameSite=None; Secure` (prod), conditional `Secure` flag | ✅ IMPLEMENTED |
| **Rate Limiting** | Redis-backed: Registration (100/hr), OTP resend (5/min), Device ops (10/hr), WebAuthn (10/hr), Global IP (1000/min) | ✅ IMPLEMENTED |
| **WebAuthn Origins** | Dev: localhost:5000, Prod: Explicit HTTPS origins via `WEBAUTHN_ORIGINS` env var | ✅ IMPLEMENTED |
| **Audit Persistence** | All security events logged to PostgreSQL (`audit_logs` table) | ✅ IMPLEMENTED |

---

## Phase 11 Security Testing Report (October 2026)

### Executive Summary

A comprehensive security assessment was conducted on VaultBase after Phase 10 (PostgreSQL + Redis Persistence). The assessment included authentication and authorization testing, OTP security, WebAuthn/FIDO2 cryptographic verification, face biometric validation, device trust lifecycle, session hijack detection, and dashboard/Socket.io security.

**Result: ✅ PASS - 279 tests passed, 0 failed**

---

### Phase 13.1 Security Remediation (October 2026)

Following the Phase 13 audit, four medium-severity issues were identified and remediated:

#### S13.1.1 Cookie Security
- **Issue**: Production deployments would fail SameSite=None without HTTPS
- **Fix**: Made `Secure` flag conditional on `NODE_ENV=production`
- **Behavior**: Development uses `SameSite=Strict`, Production uses `SameSite=None; Secure` (requires HTTPS)
- **Test**: `security-remediation.test.js` S13.1.1

#### S13.1.2 Rate Limiting
- **Issue**: Missing rate limits for registration, OTP resend, device operations, WebAuthn
- **Fix**: Added Redis-backed rate limit functions in `rateLimitStore.js`:
  - `checkRegisterRateLimit`: 100 registrations/hour per IP
  - `checkOtpResendRateLimit`: 5 resends/minute per email
  - `checkDeviceOpRateLimit`: 10 ops/hour per device
  - `checkWebAuthnRateLimit`: 10 operations/hour per user
  - `checkGlobalIpRateLimit`: 1000 requests/minute global IP cap
- **Test**: `security-remediation.test.js` S13.1.2

#### S13.1.3 WebAuthn Origin Separation
- **Issue**: Development origins (localhost) in production configuration
- **Fix**: 
  - Development: `WEBAUTHN_RP_ID=localhost`, `WEBAUTHN_ORIGIN=http://localhost:5000`
  - Production: Explicit HTTPS origins via `WEBAUTHN_ORIGINS` (comma-separated)
  - Origin validation at registration time
- **Test**: `security-remediation.test.js` S13.1.3

#### S13.1.4 Audit Persistence
- **Issue**: Audit logs not persisted to database
- **Fix**: All security events now logged to `audit_logs` table in PostgreSQL
- **Test**: `security-remediation.test.js` S13.1.4

---

### Security Controls Confirmed

| ID | Security Area | Control | Status |
|----|---------------|---------|--------|
| S01 | PostgreSQL | Database connection with parameterized queries | CONFIRMED |
| S02 | Redis | ioredis-mock fallback for tests; real Redis in production | CONFIRMED |
| S03 | Auth | JWT algorithm restricted to HS256 only | CONFIRMED |
| S04 | Auth | Issuer validation ("vaultbase") enabled | CONFIRMED |
| S05 | Auth | Server-side session validation via PostgreSQL + Redis | CONFIRMED |
| S06 | Auth | Token blacklist via Redis (session:revoked:{jti}) | CONFIRMED |
| S07 | OTP | CSPRNG generation via crypto.randomInt(100000, 1000000) | CONFIRMED |
| S08 | OTP | HMAC-SHA256 hashing with OTP_SECRET | CONFIRMED |
| S09 | OTP | Timing-safe comparison via crypto.timingSafeEqual() | CONFIRMED |
| S10 | OTP | 5-minute TTL enforcement (OTP_TTL_MS = 300000) | CONFIRMED |
| S11 | OTP | 3-attempt limit (OTP_MAX_ATTEMPTS = 3) | CONFIRMED |
| S12 | OTP | 30-second resend cooldown (OTP_RESEND_COOLDOWN_MS = 30000) | CONFIRMED |
| S13 | OTP | Single-use consumption (otpHash: null after verification) | CONFIRMED |
| S14 | WebAuthn | Challenge stored in Redis with TTL | CONFIRMED |
| S15 | WebAuthn | Single-use challenge consumption (atomic get+delete) | CONFIRMED |
| S16 | WebAuthn | UserId binding enforced | CONFIRMED |
| S17 | WebAuthn | Sign counter anomaly detection | CONFIRMED |
| S18 | Face | Descriptor validation (128D array, statistical variance check) | CONFIRMED |
| S19 | Face | Cross-user descriptor rejection | CONFIRMED |
| S20 | Face | Client liveness flag rejected - server requires valid descriptor | CONFIRMED |
| S21 | Device | Device lifecycle: NEW → TRUSTED → REVOKED | CONFIRMED |
| S22 | Device | Cross-user device isolation via email filtering | CONFIRMED |
| S23 | Device | Revoked device causes session rejection + auto-revocation | CONFIRMED |
| S24 | Session | Fingerprint mismatch = hijack detection | CONFIRMED |
| S25 | Session | IP/UA context change tracking (logs but doesn't auto-revoke) | CONFIRMED |
| S26 | Session | 1-hour token lifetime (ACCESS_TTL_S = 3600) | CONFIRMED |
| S27 | SQL | All queries use parameterized placeholders ($1, $2) | CONFIRMED |
| S28 | SQL | No string concatenation in SQL queries | CONFIRMED |
| S29 | Redis | TTL on all security-sensitive keys | CONFIRMED |
| S30 | Redis | Atomic operations for counters (redis.incr) | CONFIRMED |
| S31 | Socket.io | JWT required for connection (middleware validation) | CONFIRMED |
| S32 | Socket.io | User-specific room isolation (socket.join user:{sub}) | CONFIRMED |
| S33 | Rate | Login failure tracking with 15-min TTL | CONFIRMED |
| S34 | Rate | Cooldown on OTP resend (HTTP 429) | CONFIRMED |
| S35 | Errors | No stack traces in production responses | CONFIRMED |
| S36 | CORS | Origin whitelist with extension support | CONFIRMED |
| S37 | Cookies | HttpOnly, conditional Secure flag (`SameSite=Strict` dev, `SameSite=None; Secure` prod) | CONFIRMED |
| S38 | Rate Limit | Redis-backed registration rate limit (100/hr per IP) | CONFIRMED |
| S39 | Rate Limit | Redis-backed OTP resend rate limit (5/min per email) | CONFIRMED |
| S40 | Rate Limit | Redis-backed device operations rate limit (10/hr per device) | CONFIRMED |
| S41 | Rate Limit | Redis-backed WebAuthn rate limit (10/hr per user) | CONFIRMED |
| S42 | Rate Limit | Redis-backed global IP rate limit (1000/min per IP) | CONFIRMED |

---

### Test Results (Phase 11 + Phase 13.1)

| Suite | Tests Passed | Tests Failed | Status |
|-------|--------------|--------------|--------|
| persistence.test.js | 60 | 0 | ✅ PASS |
| auth-flow.test.js | 54 | 0 | ✅ PASS |
| session-security.test.js | 53 | 0 | ✅ PASS |
| dashboard.test.js | 39 | 0 | ✅ PASS |
| webauthn.test.js | 73 | 0 | ✅ PASS |
| security-remediation.test.js | 4 | 0 | ✅ PASS (Phase 13.1) |
| **Total** | **283** | **0** | ✅ PASS |

---

## Phase 12 Docker Deployment Security Notes

### Container Security Configuration

| Control | Implementation | Status |
|---------|----------------|--------|
| Non-root containers | All services run as `vaultbase` user | CONFIGURED |
| Minimal base images | node:18-alpine (80MB vs 900MB) | CONFIGURED |
| Health checks | PostgreSQL, Redis, Backend have health checks | CONFIGURED |
| Secret management | Via environment variables (not in images) | CONFIGURED |
| Network isolation | Internal network for DB/Redis | CONFIGURED |
| Port exposure | Only browser-facing ports exposed | CONFIGURED |
| .dockerignore | Prevents secrets from images | CONFIGURED |

### Docker Security Checklist

- [x] Non-root users in all containers
- [x] Minimal base images (Alpine Linux)
- [x] No secrets in Dockerfiles
- [x] .dockerignore prevents secret leakage
- [x] Health checks for all critical services
- [x] Network segmentation (internal vs external)
- [x] Named volumes for persistence
- [x] Restart policies configured
- [x] Read-only schema initialization

### Production Deployment Recommendations

1. **Secrets Management**
   - Use Docker secrets or external secrets manager (HashiCorp Vault, AWS Secrets Manager)
   - Never store secrets in version control
   - Rotate secrets regularly

2. **Network Security**
   - Use TLS/SSL for all production traffic
   - Configure WebAuthn RP ID and origin for HTTPS
   - Restrict PostgreSQL/Redis port exposure
   - Consider a reverse proxy (nginx, Traefik)

3. **Image Security**
   - Scan images for vulnerabilities: `trivy image vaultbase-backend`
   - Use specific image tags, not `latest`
   - Keep base images updated

4. **Resource Limits**
   - Add memory and CPU limits in docker-compose.yml
   - Monitor container resource usage

5. **Logging**
   - Centralize logs (ELK stack, CloudWatch, etc.)
   - Set log retention policies
   - Avoid logging sensitive data

### CORS Configuration

The following origins are configured in the backend:

| Origin | Purpose | Environment |
|--------|---------|-------------|
| `http://localhost:8080` | DemoBank development | Development |
| `http://localhost:3000` | Dashboard development | Development |
| `chrome-extension://*` | Chrome extension | All |
| `http://127.0.0.1:8080` | DemoBank alternative | Development |
| `http://127.0.0.1:3000` | Dashboard alternative | Development |

**For production**, configure HTTPS origins:
```yaml
ALLOWED_ORIGINS=https://demo.vaultbase.com,https://dashboard.vaultbase.com,chrome-extension://*
```

### WebAuthn Production Configuration

For production WebAuthn, configure proper HTTPS origins:

```bash
WEBAUTHN_RP_ID=vaultbase.example.com
WEBAUTHN_ORIGIN=https://vaultbase.example.com
```

**Requirements:**
- Valid TLS certificate
- Matching RP ID with effective domain
- Registered origin in browser

---

## Vulnerability Assessment

**Critical Vulnerabilities Found:** 0  
**High-Severity Issues Found:** 0  
**Medium-Severity Issues Found:** 0  
**Low-Severity Issues Found:** 0  

---

## Infrastructure Coverage

| Component | Coverage | Notes |
|-----------|----------|-------|
| PostgreSQL | Full | Docker health check configured |
| Redis | Full | Docker health check configured |
| Backend | Full | Dependency ordering via health checks |
| Dashboard | Full | Static assets only |
| DemoBank | Full | Reference application |

---

## Known Limitations

1. **Extension/DemoBank Integration**: Message passing between extension and demo-bank was not exhaustively tested for malicious payloads - this is an area for future penetration testing
2. **Real-World Biometric Accuracy**: Face verification uses Euclidean distance threshold (0.5) - actual recognition accuracy depends on face-api.js model quality in production
3. **IP Change Handling**: IP changes with matching device fingerprint are logged but do not automatically revoke sessions (by design - avoids false positives)
4. **Multi-Backend Deployment**: Session revocation consistency across multiple backend instances was not tested
5. **Chrome Extension**: Must be loaded manually in browser (standard for development)

---

## Recommendations for Future Phases

1. **Penetration Testing**: Conduct professional penetration testing before production deployment
2. **Security Headers**: Add CSP, HSTS, and X-Frame-Options headers
3. **Rate Limiting**: Add more granular rate limiting at API gateway level
4. **Audit Logging**: Enhance audit trail with tamper-evident logging
5. **Secrets Management**: Migrate from .env to proper secrets management (Vault, AWS Secrets Manager)
6. **TLS Termination**: Configure reverse proxy with TLS termination
7. **Image Scanning**: Implement CI/CD image scanning pipeline

---

## Reporting a Vulnerability

If you discover a security vulnerability within VaultBase:

1. **Do not** create a public GitHub issue.
2. Email security findings directly to `security@vaultbase.internal` (or repository owners).
3. Include detailed steps to reproduce the issue, proof of concept, and the affected component (`extension`, `backend`, etc.).
4. We aim to acknowledge receipt of vulnerability reports within 48 hours and provide remediation timelines promptly.

---

## Historical Security Hardening

### Phase 12 (Docker + Deployment)
- Containerized all services with health checks
- Non-root container execution
- Network segmentation (internal/external)
- Secret management via environment variables
- Named volumes for persistence

### Phase 10 (PostgreSQL + Redis Persistence)
- Migrated from in-memory storage to PostgreSQL for persistent state
- Redis integration for ephemeral OTP and WebAuthn challenges
- Server-side session validation added
- JTI-based token revocation

### Phase 8 (Session Security & Hijack Detection)
- JWT algorithm pinning (HS256 only)
- Server-side session record verification
- Fingerprint mismatch detection
- Session context change tracking

### Phase 7 (WebAuthn/FIDO2)
- Full WebAuthn registration and authentication flow
- Cryptographic verification via @simplewebauthn/server
- Challenge replay protection
- Sign counter anomaly detection

### Phase 6 (Face Biometrics)
- Server-side descriptor validation
- Statistical variance checks (rejects constant/fake descriptors)
- Cross-user isolation
- No client-controlled liveness bypass

### Phase 5 (Device Trust)
- Device lifecycle: NEW → TRUSTED → REVOKED
- Server-side device status evaluation
- Client trust claims ignored

### Phase 4 (Risk Engine)
- Dynamic factor policy based on risk score
- Signal-based assessment (device, IP, time, failures)
- No client-controlled risk scores accepted

### Phase 3 (Secure OTP)
- CSPRNG 6-digit OTP generation
- HMAC-SHA256 hashed storage
- Timing-safe verification
- Rate limiting and attempt tracking