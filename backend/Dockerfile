# VaultBase Backend - Production Dockerfile
FROM node:18-alpine

WORKDIR /app

# Install production dependencies only (no devDependencies)
COPY package*.json ./
RUN npm ci --only=production

# Copy application source
COPY . .

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S vaultbase -u 1001 -G nodejs && \
    chown -R vaultbase:nodejs /app && \
    mkdir -p /app/logs && \
    chown -R vaultbase:nodejs /app/logs

USER vaultbase

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:5000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

EXPOSE 5000

CMD ["node", "server.js"]
