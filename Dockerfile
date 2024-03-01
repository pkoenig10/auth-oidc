FROM --platform=$BUILDPLATFORM golang:1.22.0 AS builder

COPY . /app
WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build

FROM gcr.io/distroless/static:latest@sha256:072d78bc452a2998929a9579464e55067db4bf6d2c5f9cde582e33c10a415bd1

COPY --from=builder /app/oidc-rp /

ENTRYPOINT ["/oidc-rp"]
