# Use the official Rust image as a builder
FROM rust:1.88-slim as builder

RUN apt-get update && apt-get install -y build-essential pkg-config libssl-dev

# Create a new empty shell project
WORKDIR /usr/src/app
COPY . .

# Build the application
# Using --release for production optimization
RUN cargo build --release

# Production image
FROM debian:stable-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copy the built binary from the builder stage
COPY --from=builder /usr/src/app/target/release/ens-backend .
COPY templates ./templates

# Expose the port the app runs on
EXPOSE 4500

# Command to run the application
CMD ["./ens-backend"] 