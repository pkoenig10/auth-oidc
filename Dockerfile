FROM golang AS builder

COPY . /app

WORKDIR /app
RUN CGO_ENABLED=0 go build -o /oidc-rp

FROM alpine

COPY --from=builder /oidc-rp /

RUN apk add --no-cache \
    ca-certificates

ENTRYPOINT ["/oidc-rp"]
