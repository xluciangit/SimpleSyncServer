FROM node:25.8.1-alpine AS builder
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev

FROM node:25.8.1-alpine
RUN apk upgrade --no-cache
WORKDIR /app
COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY server.js .
COPY lib/ ./lib/
COPY routes/ ./routes/
COPY views/ ./views/
COPY static/ ./static/
RUN chown -R node:node /app
USER node
EXPOSE 3000
VOLUME ["/data", "/config"]

LABEL org.opencontainers.image.title="SimpleSync Server" \
      org.opencontainers.image.description="Self-hosted file sync server for SimpleSync Companion" \
      org.opencontainers.image.url="https://github.com/xlucian/simple-sync-server" \
      org.opencontainers.image.source="https://github.com/xlucian/simple-sync-server" \
      org.opencontainers.image.vendor="xlucian" \
      org.opencontainers.image.licenses="MIT"
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
