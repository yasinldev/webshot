# Multi-stage build for WebShot
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig \
    gcc \
    libc-dev

# Set working directory
WORKDIR /usr/src/webshot

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src/ src/

# Build the application
RUN cargo build --release

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    libstdc++ \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S webshot && \
    adduser -u 1001 -S webshot -G webshot

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /usr/src/webshot/target/release/webshot /app/webshot

# Copy configuration files
COPY webshot.toml /app/webshot.toml

# Change ownership to non-root user
RUN chown -R webshot:webshot /app

# Switch to non-root user
USER webshot

# Expose ports (for potential future web interface)
EXPOSE 8080

# Set environment variables
ENV RUST_LOG=info
ENV WEBSHOT_TIMEOUT=5
ENV WEBSHOT_CONCURRENCY=100

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/webshot --help > /dev/null 2>&1 || exit 1

# Default command
ENTRYPOINT ["/app/webshot"]

# Default arguments (can be overridden)
CMD ["--help"]
