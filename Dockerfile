FROM node:18-alpine
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
# If no settings.json provided, use the example as default
RUN if [ ! -f settings.json ]; then cp settings.example.json settings.json; fi
EXPOSE 3000
VOLUME /app/data
CMD ["node","server.js"]
