FROM --platform=$BUILDPLATFORM golang:1.21.4 AS builder

COPY . /app
WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build

FROM gcr.io/distroless/static:latest@sha256:6706c73aae2afaa8201d63cc3dda48753c09bcd6c300762251065c0f7e602b25

COPY --from=builder /app/oidc-rp /

ENTRYPOINT ["/oidc-rp"]
