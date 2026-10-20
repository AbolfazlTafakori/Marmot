# syntax=docker/dockerfile:1
# Development image of the panel alone, served by nginx and proxying the API
# to a marmot node. In production the node serves the panel itself
# (backend/Dockerfile). Build from the repository root:
#   docker build -f frontend/Dockerfile -t marmot-panel-dev .
#   docker run -p 8080:8080 -e MARMOT_API=http://host.docker.internal:7443 marmot-panel-dev

FROM node:24-bookworm-slim AS build
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY backend/api/openapi.yaml /src/backend/api/openapi.yaml
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine
ENV MARMOT_API=http://127.0.0.1:7443
COPY frontend/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /src/frontend/dist /usr/share/nginx/html
EXPOSE 8080
