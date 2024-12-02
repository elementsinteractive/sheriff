ARG GO_VERSION=1.23.2
ARG OSV_SCANNER_VERSION=1.9.0
ARG BUSYBOX_VERSION=1.37.0

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

FROM busybox:${BUSYBOX_VERSION}-uclibc AS final

WORKDIR /app

COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/build/sheriff /usr/local/bin/sheriff

ENTRYPOINT [ "sheriff" ]
