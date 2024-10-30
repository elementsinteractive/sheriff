ARG GO_VERSION=1.23.2
ARG ALPINE_VERSION=3.20.3
ARG OSV_SCANNER_VERSION=1.9.0

FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /app
# Install dependencies
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Build the application
COPY main.go main.go
COPY internal/ internal/
RUN go build -o build/

FROM ghcr.io/google/osv-scanner:v${OSV_SCANNER_VERSION} AS osv-scanner

FROM scratch AS final

WORKDIR /app

COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/build/securityscanner /usr/local/bin/securityscanner
