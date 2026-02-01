FROM --platform=$BUILDPLATFORM golang:1.25.6 AS builder

COPY . /app
WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build

FROM gcr.io/distroless/static:latest@sha256:cd64bec9cec257044ce3a8dd3620cf83b387920100332f2b041f19c4d2febf93

COPY --from=builder /app/auth-oidc /

ENTRYPOINT ["/auth-oidc"]
