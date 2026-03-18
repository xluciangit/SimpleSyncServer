FROM node:20-alpine
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js .
COPY lib/ ./lib/
COPY routes/ ./routes/
COPY views/ ./views/
COPY static/ ./static/
RUN chown -R node:node /app
USER node
EXPOSE 3000
VOLUME ["/data", "/config"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
