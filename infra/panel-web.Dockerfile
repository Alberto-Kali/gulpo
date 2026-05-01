FROM node:22-alpine AS deps
WORKDIR /app
COPY apps/panel-web/package.json apps/panel-web/package-lock.json* ./
RUN npm install

FROM node:22-alpine AS builder
WORKDIR /app
ARG NEXT_PUBLIC_PANEL_BASE_PATH=""
ENV NEXT_PUBLIC_PANEL_BASE_PATH=$NEXT_PUBLIC_PANEL_BASE_PATH
COPY --from=deps /app/node_modules ./node_modules
COPY apps/panel-web ./
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_PUBLIC_PANEL_BASE_PATH=/panel
COPY --from=builder /app ./
EXPOSE 3000
CMD ["npm", "run", "start"]
