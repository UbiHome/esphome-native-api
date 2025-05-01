# Makefile

# Default target
all: build

# Build the Cargo package
build:
	cd generator && cargo run
	cargo build

# Clean the build artifacts
clean:
	cargo clean

# Run the application
run:
	cargo run

# Test the application
test:
	cargo test