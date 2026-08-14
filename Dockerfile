# syntax=docker/dockerfile:1
# ============================================================================
# OpticTrace — multi-stage build
#   Stage 1: build the Next.js dashboard (static export)
#   Stage 2: build the Go agent (pure Go, CGO disabled — modernc SQLite)
#   Stage 3: minimal runtime image
# ============================================================================

FROM node:22-alpine AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY ui/ .
RUN npm run build   # -> /src/ui/out

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/optictrace ./cmd/optictrace

FROM alpine:3.20
RUN addgroup -S optic && adduser -S optic -G optic \
    && mkdir -p /data && chown optic:optic /data
COPY --from=build /out/optictrace /usr/local/bin/optictrace
COPY --from=ui /src/ui/out /usr/share/optictrace/ui
COPY optic.yaml /etc/optictrace/optic.yaml
USER optic
WORKDIR /data
# 8080: proxied traffic · 9095: admin (metrics, dashboard, APIs)
EXPOSE 8080 9095
ENTRYPOINT ["optictrace"]
CMD ["run", "-config", "/etc/optictrace/optic.yaml", "-ui", "/usr/share/optictrace/ui"]
