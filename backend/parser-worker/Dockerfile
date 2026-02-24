# Use Node.js LTS as base image
FROM node:20-slim

# Install git (needed for simple-git)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci

# Copy source code
COPY src ./src

# Build TypeScript
RUN npm run build

# Remove dev dependencies, source files, and tsconfig to reduce image size
RUN rm -rf src tsconfig.json && npm ci --only=production

# Run the worker
CMD ["node", "dist/index.js"]
