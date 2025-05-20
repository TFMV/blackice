FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache ca-certificates git gcc g++ make

# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bin/flightgw cmd/flightgw/main.go

# Create runtime image
FROM alpine:3.19

WORKDIR /app

# Install required runtime packages
RUN apk add --no-cache ca-certificates tzdata

# Copy the binary from the builder stage
COPY --from=builder /app/bin/flightgw /app/flightgw

# Create directories for configs and data
RUN mkdir -p /app/config /app/certs /app/secrets /app/logs

# Copy configuration
COPY cmd/flightgw/config.yaml /app/config/

# Set the entrypoint
ENTRYPOINT ["/app/flightgw", "-config", "/app/config/config.yaml"]

# Expose the server port
EXPOSE 8815 9090 9091

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -qO- http://localhost:9091/health || exit 1 