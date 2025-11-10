# Scout Security Scanner - Docker Image

FROM node:18-alpine AS builder

# Install Python and build dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    build-base \
    python3-dev

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install Node dependencies
RUN npm ci

# Copy source code
COPY src ./src

# Build TypeScript
RUN npm run build

# Production image
FROM node:18-alpine

# Install Python and runtime dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip

# Install Slither (optional)
RUN pip3 install slither-analyzer --break-system-packages || true

# Create app user
RUN addgroup -g 1001 scout && \
    adduser -D -u 1001 -G scout scout

# Set working directory
WORKDIR /app

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Copy configuration and contracts
COPY config ./config
COPY contracts ./contracts

# Create output directories
RUN mkdir -p reports pocs artifacts logs && \
    chown -R scout:scout /app

# Switch to non-root user
USER scout

# Set environment
ENV NODE_ENV=production \
    LOG_LEVEL=info

# Expose API port (if running server)
EXPOSE 3000

# Default command
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["--help"]
