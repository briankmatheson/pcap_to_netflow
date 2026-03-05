BIN     := pcap_to_netflow
TARGET  := target/release/$(BIN)
TARBALL := $(BIN).tar.gz

.PHONY: all build release debug check test clean tarball install

all: release

## Build optimised release binary
release:
	cargo build --release

## Build debug binary
debug:
	cargo build

## Run clippy + fmt check
check:
	cargo clippy -- -D warnings
	cargo fmt --check

## Run tests
test:
	cargo test

## Strip + package binary + source into a tarball
tarball: release
	@echo "→ Stripping binary..."
	strip $(TARGET)
	@echo "→ Creating $(TARBALL) ..."
	tar -czf $(TARBALL) \
		--transform 's|^|$(BIN)/|' \
		$(TARGET) \
		Cargo.toml \
		Cargo.lock \
		src/ \
		Makefile \
		README.md
	@echo "✓ $(TARBALL) created ($$(du -sh $(TARBALL) | cut -f1))"

## Install binary to /usr/local/bin
install: release
	install -m 755 $(TARGET) /usr/local/bin/$(BIN)
	@echo "✓ Installed to /usr/local/bin/$(BIN)"

## Remove build artefacts
clean:
	cargo clean
	rm -f $(TARBALL)

## Print help
help:
	@grep -E '^##' Makefile | sed 's/## /  /'
