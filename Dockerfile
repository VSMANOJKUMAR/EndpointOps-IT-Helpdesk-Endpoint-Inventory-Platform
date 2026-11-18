FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN apk add --no-cache python3 make g++ && npm ci --omit=dev && apk del python3 make g++
COPY . .
ENV NODE_ENV=production PORT=3000 DB_FILE=/data/data.db
VOLUME /data
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://localhost:3000/api/health || exit 1
CMD ["node", "src/server.js"]
