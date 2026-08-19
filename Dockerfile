# syntax=docker/dockerfile:1
# ============================================================================
# OpticTrace — multi-stage build
#   Stage 1: build the Next.js dashboard (static export)
#   Stage 2: build the Go agent (pure Go, CGO disabled — modernc SQLite)
#   Stage 3: minimal runtime image
#
# Both build stages are pinned to $BUILDPLATFORM and cross-compile to
# $TARGETARCH. Without those pins, buildx builds every stage once per target
# platform — so a `--platform linux/amd64,linux/arm64` build ran the whole
# Next.js compile a second time under QEMU emulation, which took this from
# minutes to the better part of an hour and eventually never finished at all.
#
# Nothing here needs emulation: the dashboard is a static export and is
# architecture-independent, and the agent is pure Go with CGO off, so GOARCH is
# all it takes to target another architecture.
# ============================================================================

FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json* ./
# `npm ci` when a lockfile is present: an image build must be reproducible, and
# `npm install` is free to resolve a different tree than the one that was tested.
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; \
    else npm install --no-audit --no-fund; fi
COPY ui/ .
RUN npm run build   # -> /src/ui/out (static, architecture-independent)

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
# Supplied by buildx for each requested platform.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
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
