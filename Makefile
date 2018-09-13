all: test

build:
	@cargo build --all-features

doc:
	@cargo doc

test: cargotest

cargotest:
	@cargo test --all-features

format:
	@rustup component add rustfmt-preview 2> /dev/null
	@cargo fmt

format-check:
	@rustup component add rustfmt-preview 2> /dev/null
	@cargo fmt -- --check

lint:
	@rustup component add clippy-preview 2> /dev/null
	@cargo clippy --all-features --tests -- -D clippy

.PHONY: all doc test cargotest format format-check lint
