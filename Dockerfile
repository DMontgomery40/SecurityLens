# ---- Build stage --------------------------------------------------------
FROM node:18-alpine AS builder

# Create app directory
WORKDIR /app

# Copy dependency manifests first for better layer caching
COPY package*.json ./

# Install all dependencies (including dev-deps needed for build)
RUN npm ci

# Copy source code
COPY . .

# Build the production assets
RUN npm run build

# ---- Runtime stage ------------------------------------------------------
FROM node:18-alpine AS runtime
LABEL maintainer="SecurityLens Team"

# Set working directory
WORKDIR /app

# Copy only the necessary artifacts from the builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/src ./src

# Install production dependencies only
RUN npm ci --omit=dev --ignore-scripts \
    && npm install -g . --omit=dev --ignore-scripts

# Application port (vite preview default)
EXPOSE 4173

# By default, start the static site preview server.
# Users can override the command to run the CLI, e.g.:
#   docker run --rm securitylens securitylens scan /data
CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "4173"]