# Stage 1: Build the binary
FROM rust:alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Create a temporary working directory
WORKDIR /usr/src/entrors
COPY . .

# Build the project in release mode
RUN cargo build --release

# Stage 2: Minimal runtime image
FROM alpine:latest

# Set working directory
WORKDIR /usr/local/bin

# Copy the binary from the builder stage
COPY --from=builder /usr/src/entrors/target/release/EntroRS .

# Ensure the binary has execution permissions
RUN chmod +x EntroRS

# Define the entrypoint for the container
ENTRYPOINT ["./EntroRS"]

# Default command (empty, as the entrypoint handles the binary)
CMD ["--help"]
