# Makefile

# Default target
all: build

# test
src/proto/mod.rs:
	echo generate protos
	cd generator && cargo run

# Build the Cargo package
build: src/proto/mod.rs
	cargo build

# Clean the build artifacts
clean:
	cd generator && cargo clean
	cargo clean

# Test the application
test:
	cargo test

e2e-test:
	cd tests
	uv run pytest

e2e-matrix:
	cargo build --examples
	cd tests
	tox