FROM golang:1.15-alpine3.12 AS builder

COPY . /app

WORKDIR /app
RUN go build -o /oidc-rp

FROM alpine:3.12

COPY --from=builder /oidc-rp /

RUN apk add --no-cache \
    ca-certificates

ENTRYPOINT ["/oidc-rp"]
