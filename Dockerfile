FROM --platform=$BUILDPLATFORM golang:1.23.0 AS builder

COPY . /app
WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build

FROM gcr.io/distroless/static:latest@sha256:ce46866b3a5170db3b49364900fb3168dc0833dfb46c26da5c77f22abb01d8c3

COPY --from=builder /app/auth-oidc /

ENTRYPOINT ["/auth-oidc"]
