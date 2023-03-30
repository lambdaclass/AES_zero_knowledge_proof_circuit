.PHONY: clippy test

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo insta test

benchmarks:
	cargo criterion --bench benchmark

install_insta:
	cargo install cargo-insta

insta_demo:
	cargo insta test --review -- test_aes_encryption_step_by_step

clean_snapshots:
	rm -rf tests/snapshots
