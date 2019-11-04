FROM golang:alpine AS builder

COPY . /app

WORKDIR /app
RUN go build -o /oidc-rp

FROM alpine

COPY --from=builder /oidc-rp /

RUN apk add --no-cache \
    ca-certificates

ENTRYPOINT ["/oidc-rp"]
