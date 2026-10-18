# VaultBase Dashboard - Multi-stage build for production
# Stage 1: Build stage (if using Vite or similar bundler)
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source files
COPY src/ ./src/
COPY styles/ ./styles/
COPY index.html ./

# Build the React application (uncomment if using Vite/Webpack)
# RUN npm run build

# Stage 2: Production runtime
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy built assets from builder stage
COPY --from=builder /app ./

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S vaultbase -u 1001 -G nodejs && \
    chown -R vaultbase:nodejs /app

USER vaultbase

EXPOSE 3000

CMD ["node", "server.js"]