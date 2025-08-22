# WebShot Makefile
# Provides common development and build commands

.PHONY: help build release test clean install uninstall fmt clippy check docs run-example

# Default target
help:
	@echo "WebShot - Professional Network Scanner"
	@echo ""
	@echo "Available commands:"
	@echo "  build        - Build the project in debug mode"
	@echo "  release      - Build the project in release mode"
	@echo "  test         - Run all tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install WebShot globally"
	@echo "  uninstall    - Uninstall WebShot"
	@echo "  fmt          - Format code with rustfmt"
	@echo "  clippy       - Run clippy linter"
	@echo "  check        - Check code without building"
	@echo "  docs         - Generate documentation"
	@echo "  run-example  - Run example scan"
	@echo "  bench        - Run benchmarks"
	@echo "  coverage     - Generate test coverage report"
	@echo "  docker       - Build Docker image"
	@echo "  docker-run   - Run Docker container"

# Build targets
build:
	cargo build

release:
	cargo build --release

# Testing
test:
	cargo test

test-verbose:
	cargo test -- --nocapture

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/
	rm -rf dist/

# Installation
install:
	cargo install --path .

uninstall:
	cargo uninstall webshot

# Code quality
fmt:
	cargo fmt

clippy:
	cargo clippy

check:
	cargo check

# Documentation
docs:
	cargo doc --open

# Example usage
run-example:
	cargo run -- 127.0.0.1 80,443,22

# Benchmarks
bench:
	cargo bench

# Test coverage (requires cargo-tarpaulin)
coverage:
	cargo install cargo-tarpaulin
	cargo tarpaulin --out Html

# Docker
docker:
	docker build -t webshot .

docker-run:
	docker run --rm -it webshot --help

# Development helpers
dev-setup:
	cargo install cargo-watch
	cargo install cargo-tarpaulin
	cargo install cargo-audit

watch:
	cargo watch -x run

watch-test:
	cargo watch -x test

# Security
audit:
	cargo audit

# Performance profiling
profile:
	cargo install flamegraph
	cargo flamegraph -- 127.0.0.1 80,443

# Cross-compilation
cross-build-linux:
	cargo install cross
	cross build --target x86_64-unknown-linux-gnu --release

cross-build-windows:
	cross build --target x86_64-pc-windows-gnu --release

cross-build-macos:
	cross build --target x86_64-apple-darwin --release

# Package management
update-deps:
	cargo update

outdated:
	cargo install cargo-outdated
	cargo outdated

# Git helpers
pre-commit: fmt clippy test
	@echo "Pre-commit checks passed!"

# CI/CD
ci: check test clippy
	@echo "CI checks passed!"

# Release preparation
release-prep: clean test clippy audit
	cargo build --release
	@echo "Release build completed successfully!"

# Helpers for different platforms
install-macos:
	brew install rust
	make dev-setup

install-ubuntu:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	sudo apt-get install -y build-essential
	make dev-setup

install-windows:
	# Download and run rustup-init.exe from https://rustup.rs/
	@echo "Please download rustup-init.exe from https://rustup.rs/ and run it"
	@echo "Then run: make dev-setup"

# Quick development cycle
dev: fmt clippy test run-example

# Full development cycle
full-dev: clean dev-setup fmt clippy test coverage audit

# Show project info
info:
	@echo "WebShot Project Information:"
	@echo "Version: $(shell grep '^version = ' Cargo.toml | cut -d'"' -f2)"
	@echo "Rust Version: $(shell rustc --version)"
	@echo "Cargo Version: $(shell cargo --version)"
	@echo "Target Directory: $(shell cargo metadata --format-version 1 | jq -r '.target_directory')"
