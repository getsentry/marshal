all: test

build:
	@cargo build --all-features

doc:
	@cargo doc

test: cargotest

cargotest:
	@cargo test --all-features

format:
	@cargo fmt

format-check:
	@cargo fmt -- --write-mode diff

lint:
	@cargo +nightly clippy --all-features --tests -- -D clippy

.PHONY: all doc test cargotest format-check lint
