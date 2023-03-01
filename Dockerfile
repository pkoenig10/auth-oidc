FROM --platform=$BUILDPLATFORM golang:1.20.1 AS builder

COPY . /app
WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build

FROM gcr.io/distroless/static:latest@sha256:3c5767883bc3ad6c4ad7caf97f313e482f500f2c214f78e452ac1ca932e1bf7f

COPY --from=builder /app/oidc-rp /

ENTRYPOINT ["/oidc-rp"]
