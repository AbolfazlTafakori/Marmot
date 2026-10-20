# syntax=docker/dockerfile:1
# Marmot node image: the binary and the built panel, on distroless, non-root.
# Build from the repository root:
#   docker build -f backend/Dockerfile -t marmot .

# --- panel ---------------------------------------------------------------
FROM node:24-bookworm-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY backend/api/openapi.yaml /src/backend/api/openapi.yaml
COPY frontend/ ./
RUN npm run build

# --- binary --------------------------------------------------------------
FROM golang:1.27-bookworm AS bin
ARG VERSION=dev
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/marmot ./cmd/marmot
# Let the non-root user bind user-facing ports below 1024 (443, 80).
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libcap2-bin >/dev/null \
 && setcap cap_net_bind_service=+ep /out/marmot

# --- runtime -------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=bin /out/marmot /usr/local/bin/marmot
COPY --from=web /src/frontend/dist /usr/share/marmot/web
# Config and identity live in /etc/marmot (a directory, so the panel can
# replace marmot.toml atomically); the panel database in /var/lib/marmot.
VOLUME ["/etc/marmot", "/var/lib/marmot"]
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/marmot", "health", "-config", "/etc/marmot/marmot.toml"]
ENTRYPOINT ["/usr/local/bin/marmot"]
CMD ["run", "-config", "/etc/marmot/marmot.toml"]
