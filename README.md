# VaultBase

VaultBase is a **passwordless authentication ecosystem** built around **"Sign in with VaultBase"** — delivering a streamlined user experience similar to "Sign in with Google/GitHub", but powered by multi-factor biometric and cryptographic verification.

The Chrome Extension detects participating login pages and allows users to authenticate using face biometrics, device trust, and WebAuthn FIDO2 credentials. VaultBase verifies identity and protects resulting sessions with server-side validation and real-time security monitoring.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Face Biometrics** | Client-side face detection/recognition via TensorFlow.js (face-api.js) with server-side descriptor validation |
| **WebAuthn/FIDO2** | Platform authenticator support with cryptographic challenge-response verification |
| **Device Trust** | Device fingerprinting and lifecycle management (NEW → TRUSTED → REVOKED) |
| **Risk-Based Auth** | Dynamic authentication factors based on risk scoring signals |
| **Secure OTP** | 6-digit time-limited OTPs with HMAC-SHA256 storage and timing-safe comparison |
| **Session Security** | JWT tokens with server-side validation, JTI revocation, and hijack detection |

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Node.js 18+, Express, PostgreSQL 15, Redis 7 |
| **Frontend** | React 18, Socket.io Client |
| **Browser** | Chrome Extension (Manifest V3) |
| **Biometrics** | TensorFlow.js, face-api.js (128D face descriptors) |
| **Auth** | @simplewebauthn/server (WebAuthn/FIDO2) |
| **Containerization** | Docker, Docker Compose

---

## Architecture Overview

```
VaultBase/
├── backend/              # Node.js Auth API (PostgreSQL + Redis)
├── dashboard/            # React Security Dashboard
├── database/             # PostgreSQL data & Redis persistence
├── docker-compose.yml    # Full stack orchestration
├── .env.example          # Environment template
├── .gitignore            # Security-sensitive file patterns
├── README.md             # This file
└── SECURITY.md           # Security policy, controls, and disclosure guidelines
```

### Core Components

1. **Backend Infrastructure (`backend/`)**
   - Core authentication & security engine (Node.js/Express)
   - Multi-step authentication: credential verification, email OTP, biometric challenges, session tokens
   - PostgreSQL for persistent storage (users, credentials, devices, sessions, audit logs)
   - Redis for ephemeral OTP, WebAuthn challenges, session cache, and rate limiting

2. **Security Dashboard (`dashboard/`)**
   - React-based control center for security management
   - View active sessions, manage trusted devices, review audit logs and security alerts
   - Real-time updates via Socket.io

3. **DemoBank (`demo-bank/`)**
   - Reference implementation of a consumer banking application configured with VaultBase login integration
   - Serves on `http://localhost:8080`

4. **Chrome Extension (`extension/`)**
   - Primary user-facing Chrome Extension (Manifest V3)
   - Detects participating login pages, injects "Sign in with VaultBase" UI buttons
   - Conducts local biometric face detection/recognition via TensorFlow.js (face-api.js)
   - Manages device-level cryptographic authentication tokens

4. **Docker Orchestration**
   - All services containerized with health checks
   - Network segmentation (internal DB/Redis network, external browser-facing network)
   - Dependency ordering via health checks
   - Named volumes for persistence

5. **Data Layer (`database/`)**
   - **PostgreSQL 15**: Identity profiles, credentials, trusted devices, sessions, audit trails, risk events, security alerts
   - **Redis 7**: OTP storage, WebAuthn challenges, session cache, rate limiting counters

---

## Quick Start with Docker Compose

### Prerequisites

- Docker Engine 20.10+
- Docker Compose V2
- 4GB available RAM
- Ports 5000, 3000, 8080, 5432, 6379 available

### 1. Clone and Setup

```bash
git clone <repository-url>
cd VaultBase
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit with your secrets (required for production)
# nano .env
```

**Important**: Update `JWT_SECRET` and `OTP_SECRET` with strong random values for production:

```bash
# Generate secure secrets
openssl rand -hex 32  # For JWT_SECRET
openssl rand -hex 32  # For OTP_SECRET
```

### 3. Start Services

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Check service status
docker compose ps
```

### 4. Verify Services

```bash
# Check backend health
curl http://localhost:5000/health

# Expected response:
# {"status":"ok","service":"VaultBase Auth API","postgres":"connected","redis":"connected"}
```

### 5. Access Applications

| Service | URL | Description |
|---------|-----|-------------|
| Backend API | http://localhost:5000 | Auth API and health checks |
| DemoBank | http://localhost:8080 | Reference application |
| Dashboard | http://localhost:3000 | Security control center |

---

## Docker Compose Services

### Service Overview

| Service | Container | Port | Health Check | Description |
|---------|-----------|------|--------------|-------------|
| postgres | vaultbase-postgres | 5432 | `pg_isready` | PostgreSQL 15 database |
| redis | vaultbase-redis | 6379 | `redis-cli ping` | Redis 7 cache |
| backend | vaultbase-backend | 5000 | `/health` endpoint | Auth API server |
| demo-bank | vaultbase-demo-bank | 8080 | - | Reference application |
| dashboard | vaultbase-dashboard | 3000 | - | Security dashboard |

### Networks

- **vaultbase_internal**: Internal network for PostgreSQL and Redis (not accessible from host)
- **vaultbase_external**: External network for browser-facing services

### Persistence

```bash
# Data locations (bind mounts)
./data/postgres/  # PostgreSQL data
./data/redis/     # Redis data (AOF)

# Named volume (Docker managed)
postgres_data     # Alternative PostgreSQL storage
redis_data        # Alternative Redis storage
```

---

## Development Mode (Hot Reload)

For development with hot reload, mount source volumes instead of using the production images:

```bash
# Override with development configuration
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Create `docker-compose.dev.yml`:

```yaml
version: '3.8'

services:
  backend:
    volumes:
      - ./backend:/app
      - /app/node_modules
    environment:
      - NODE_ENV=development

  demo-bank:
    volumes:
      - ./demo-bank:/app

  dashboard:
    volumes:
      - ./dashboard/src:/app/src
```

---

## Stopping and Restarting

```bash
# Stop all services (preserves data)
docker compose down

# Stop and remove volumes (DELETES ALL DATA!)
docker compose down -v

# Restart a single service
docker compose restart backend

# View logs for specific service
docker compose logs -f backend
```

### Safe Shutdown Procedure

```bash
# 1. Stop accepting new connections (optional)
docker compose stop backend

# 2. Wait for existing connections to close
sleep 5

# 3. Stop remaining services
docker compose stop postgres redis

# 4. Data is preserved in ./data/ directory
```

---

## Chrome Extension Setup

### Load Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in upper right)
3. Click **Load unpacked**
4. Select the `extension/` directory from this repository
5. Navigate to `http://localhost:8080` to test the "Sign in with VaultBase" flow

### Extension Permissions

The extension requires:
- **Webcam access**: For face biometric verification
- **Storage**: For local device credentials
- **Host permissions**: To communicate with backend and inject into login pages

---

## Testing

### Run All Tests

```bash
# Run from backend directory
cd backend
npm test

# Or via Docker
docker compose exec backend npm test
```

### Test Suites

| Suite | Description |
|-------|-------------|
| persistence.test.js | Database and Redis persistence |
| auth-flow.test.js | Authentication flow |
| session-security.test.js | Session hijack detection |
| dashboard.test.js | Dashboard functionality |
| webauthn.test.js | WebAuthn/FIDO2 verification |

---

## Troubleshooting

### Services Not Starting

```bash
# Check service status
docker compose ps

# Check logs for errors
docker compose logs postgres
docker compose logs redis
docker compose logs backend
```

### Database Connection Issues

```bash
# Verify PostgreSQL is healthy
docker compose exec postgres pg_isready -U vaultbase_admin

# Check PostgreSQL logs
docker compose logs postgres
```

### Redis Connection Issues

```bash
# Verify Redis is healthy
docker compose exec redis redis-cli ping

# Check Redis logs
docker compose logs redis
```

### Backend Not Starting

```bash
# Check backend logs
docker compose logs backend

# Verify environment variables
docker compose exec backend env | grep -E "(POSTGRES|REDIS|JWT)"
```

### Port Conflicts

If ports are already in use:

```bash
# Check what's using the port
netstat -ano | findstr :5000

# Modify ports in docker-compose.yml or stop conflicting services
```

### Clear All Data and Restart

```bash
# Stop services and remove volumes
docker compose down -v

# Recreate data directories (if using bind mounts)
rm -rf data/*
mkdir -p data/postgres data/redis

# Restart
docker compose up -d
```

---

## Environment Variables Reference

### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | JWT signing secret | (must be set) |
| `OTP_SECRET` | OTP HMAC secret | (must be set) |
| `POSTGRES_PASSWORD` | Database password | vaultbase_dev_secret |
| `REDIS_PASSWORD` | Redis password | (empty) |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | development |
| `WEBAUTHN_RP_ID` | WebAuthn RP ID | localhost |
| `WEBAUTHN_ORIGIN` | WebAuthn origin | http://localhost:5000 |
| `ALLOWED_ORIGINS` | CORS origins | (see .env.example) |

---

## Security Notes

- **NEVER** commit real `.env` files or secrets
- **ALWAYS** use strong, random secrets for production
- **DO NOT** expose PostgreSQL or Redis ports in production
- **USE** HTTPS in production for all services
- **ROTATE** secrets periodically in production environments

---

## Documentation

- [Backend Documentation](docs/backend.md)
- [Extension Setup Guide](docs/extension-setup.md)
- [Security Policy & Disclosures](SECURITY.md)

---

## License

Proprietary — VaultBase Security Inc.