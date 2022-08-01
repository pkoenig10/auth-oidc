FROM --platform=$BUILDPLATFORM golang:1.18.4 AS builder

COPY . /app
WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build

FROM gcr.io/distroless/static

COPY --from=builder /app/oidc-rp /

ENTRYPOINT ["/oidc-rp"]
