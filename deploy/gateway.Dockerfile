# Multi-stage build for the CompliantAI gateway binary.
# Final image is non-root, minimal, and free of build tooling.

FROM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath \
    -ldflags "-s -w -X 'github.com/raphbaph/CompliantAI/internal/version.Version=${VERSION}' -X 'github.com/raphbaph/CompliantAI/internal/version.Commit=${COMMIT}' -X 'github.com/raphbaph/CompliantAI/internal/version.BuildTime=${BUILD_TIME}'" \
    -o /out/gateway ./cmd/gateway

# Distroless static nonroot: no shell, no package manager, uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot

USER nonroot:nonroot
WORKDIR /

COPY --from=build --chown=nonroot:nonroot /out/gateway /gateway

# Config and secrets are mounted at runtime; image contains only the binary.
EXPOSE 8443

ENTRYPOINT ["/gateway"]
