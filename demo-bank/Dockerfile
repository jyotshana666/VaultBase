# DemoBank - Production Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files first for better layer caching
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy application source
COPY . .

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S vaultbase -u 1001 -G nodejs && \
    chown -R vaultbase:nodejs /app

USER vaultbase

EXPOSE 8080

CMD ["node", "server.js"]
