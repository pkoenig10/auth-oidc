FROM golang:1.17.5 AS builder

COPY . /app

WORKDIR /app
RUN go build -o /oidc-rp

FROM gcr.io/distroless/base

COPY --from=builder /oidc-rp /

ENTRYPOINT ["/oidc-rp"]
