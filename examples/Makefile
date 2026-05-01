# sidestep Track B — spine fixtures + 3 asserts (bd aae-orc-kdz1).
#
# Asserts simulate v0.1 primitive flows in jq + shell so they run today,
# pre-Rust. They become regression input for the eventual Rust implementation:
# the Rust output of `list | filter | emit` etc. should match these jq
# simulations on the same fixtures.

.PHONY: assert assert-01 assert-02 assert-03

assert: assert-01 assert-02 assert-03
	@echo
	@echo "all asserts passed."

assert-01:
	@bash asserts/01-round-trip.sh

assert-02:
	@bash asserts/02-cross-kind-enrich.sh

assert-03:
	@bash asserts/03-rank-stability.sh
