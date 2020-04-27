FROM golang:1.14-alpine3.11 AS builder

COPY . /app

WORKDIR /app
RUN go build -o /oidc-rp

FROM alpine:3.11

COPY --from=builder /oidc-rp /

RUN apk add --no-cache \
    ca-certificates

ENTRYPOINT ["/oidc-rp"]
