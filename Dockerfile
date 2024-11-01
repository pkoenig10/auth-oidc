FROM --platform=$BUILDPLATFORM golang:1.23.2 AS builder

COPY . /app
WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build

FROM gcr.io/distroless/static:latest@sha256:cc226ca14d17d01d4b278d9489da930a0dd11150df10ae95829d13e6d00fbdbf

COPY --from=builder /app/auth-oidc /

ENTRYPOINT ["/auth-oidc"]
