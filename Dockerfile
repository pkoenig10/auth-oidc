FROM --platform=$BUILDPLATFORM golang:1.22.1 AS builder

COPY . /app
WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build

FROM gcr.io/distroless/static:latest@sha256:046b92c933032a8ca99a66f4c79a68ac029d9a4ababd1a806a82140b3b899fd3

COPY --from=builder /app/oidc-rp /

ENTRYPOINT ["/oidc-rp"]
