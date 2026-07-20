# chat-xdk Makefile
# Run `make help` for available targets

.PHONY: all build release test test-verbose check clean codegen fmt fmt-check lint doc help test-sdks test-js test-py go-lib prebuilt prebuilt-linux-amd64 prebuilt-linux-amd64-musl prebuilt-all test-go dotnet-build dotnet-test jvm-test versions set-version wheel wheel-dev wasm wasm-node wasm-bundler ci

# Detect host platform for prebuilt target
HOST_OS   := $(shell go env GOOS 2>/dev/null)
HOST_ARCH := $(shell go env GOARCH 2>/dev/null)

# Default target
all: check test

# Build all crates
build:
	cargo build --workspace

# Build release
release:
	cargo build --workspace --release

# Show the version of every binding (single source of truth: workspace Cargo.toml)
versions:
	@./scripts/version.sh list

# Set/bump the unified version across all bindings, e.g. `make set-version V=0.2.0`
set-version:
	@./scripts/version.sh set $(V)

# Run all tests
test:
	cargo test --workspace

# Run Rust + Python + Node (WASM) + Go SDK tests (no Juicebox network calls).
test-sdks: test test-py test-js test-go

test-py:
	PYTHONPATH=crates/pyo3/python python3 -m unittest discover -s crates/pyo3/python/tests -v

test-js:
	node crates/wasm/js/tests/sdk_vectors.test.mjs
	node crates/wasm/js/tests/api.test.mjs
	node crates/wasm/js/tests/wrapper.test.mjs

# Build Go static library.
# On darwin, build with a single codegen unit so the archive is reproducible
# (parallel codegen makes the macOS object code vary run-to-run), and
# ZERO_AR_DATE=1 so cctools ar/ranlib/libtool stamp zeroed member dates.
go-lib:
	ZERO_AR_DATE=1 CARGO_TARGET_DIR=$(CURDIR)/target MACOSX_DEPLOYMENT_TARGET=11.0 $(if $(filter darwin,$(HOST_OS)),RUSTFLAGS="-C codegen-units=1") cargo build -p chat-xdk-go --release

# Copy the compiled static library into libs/<os>_<arch>/ for distribution.
# Run this after making Rust changes, then commit the updated .a file.
# darwin: strip under ZERO_AR_DATE, then zero every ar member date field so the
# archive is byte-reproducible (must stay identical to go-prebuilt-darwin.yml).
# linux: GNU strip -D keeps the archive in deterministic mode.
prebuilt: go-lib
	@echo "Copying libchat_xdk_go.a for $(HOST_OS)_$(HOST_ARCH)"
	@mkdir -p go/chatxdk/libs/$(HOST_OS)_$(HOST_ARCH)
	cp target/release/libchat_xdk_go.a go/chatxdk/libs/$(HOST_OS)_$(HOST_ARCH)/libchat_xdk_go.a
	@if [ "$(HOST_OS)" = "darwin" ]; then \
		ZERO_AR_DATE=1 strip -S go/chatxdk/libs/$(HOST_OS)_$(HOST_ARCH)/libchat_xdk_go.a; \
		python3 scripts/normalize_ar_dates.py go/chatxdk/libs/$(HOST_OS)_$(HOST_ARCH)/libchat_xdk_go.a; \
	else \
		strip -D --strip-debug go/chatxdk/libs/$(HOST_OS)_$(HOST_ARCH)/libchat_xdk_go.a 2>/dev/null || true; \
	fi
	@echo "Done. Commit go/chatxdk/libs/$(HOST_OS)_$(HOST_ARCH)/libchat_xdk_go.a"

# Cross-compile for Linux amd64 (glibc) from macOS using cargo-zigbuild.
# Requires: brew install zig && cargo install cargo-zigbuild && rustup target add x86_64-unknown-linux-gnu
prebuilt-linux-amd64:
	cargo zigbuild -p chat-xdk-go --release --target x86_64-unknown-linux-gnu
	@mkdir -p go/chatxdk/libs/linux_amd64
	cp target/x86_64-unknown-linux-gnu/release/libchat_xdk_go.a go/chatxdk/libs/linux_amd64/libchat_xdk_go.a
	@echo "Done. Commit go/chatxdk/libs/linux_amd64/libchat_xdk_go.a"

# Cross-compile for Linux amd64 (musl/Alpine) from macOS using cargo-zigbuild.
# Requires: brew install zig && cargo install cargo-zigbuild && rustup target add x86_64-unknown-linux-musl
prebuilt-linux-amd64-musl:
	cargo zigbuild -p chat-xdk-go --release --target x86_64-unknown-linux-musl
	@mkdir -p go/chatxdk/libs/linux_amd64_musl
	cp target/x86_64-unknown-linux-musl/release/libchat_xdk_go.a go/chatxdk/libs/linux_amd64_musl/libchat_xdk_go.a
	@echo "Done. Commit go/chatxdk/libs/linux_amd64_musl/libchat_xdk_go.a"

# Regenerate all prebuilt binaries from macOS (native + cross-compiled).
# Run this after any Rust changes, then commit the updated .a files.
prebuilt-all: prebuilt prebuilt-linux-amd64 prebuilt-linux-amd64-musl

# Run Go tests (builds the Rust static library and copies to libs/ first)
test-go: prebuilt
	cd go/chatxdk && CGO_ENABLED=1 go test -v ./...

# Run tests with output
test-verbose:
	cargo test --workspace -- --nocapture

# Check compilation without building
check:
	cargo check --workspace

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Run clippy lints
lint:
	cargo clippy --workspace --all-targets -- -D warnings

# Generate types from thrift schemas.
#
# Uses the thrift compiler built from the same apache/thrift checkout that
# Cargo already cloned for the runtime library ([patch.crates-io] in Cargo.toml).
# No separate clone required — Cargo's git checkout is reused.
#
# The built compiler is cached in .thrift-compiler/ and reused on
# subsequent runs.  Delete that directory to force a rebuild.
#
# Prerequisites: cmake, bison >= 3 (brew install bison on macOS)

THRIFT_COMPILER_CACHE := $(CURDIR)/.thrift-compiler/thrift

# Locate Cargo's git checkout of the patched thrift fork.
# The manifest is at <checkout>/lib/rs/Cargo.toml; we want the repo root.
THRIFT_CARGO_SRC := $(shell cargo metadata --format-version 1 2>/dev/null | \
	python3 -c "import sys,json; \
	pkgs=[p for p in json.load(sys.stdin)['packages'] \
	      if p['name']=='thrift' and (p.get('source') or '').startswith('git+')]; \
	print(pkgs[0]['manifest_path'].removesuffix('/lib/rs/Cargo.toml') if pkgs else '')" 2>/dev/null)

$(THRIFT_COMPILER_CACHE):
	@[ -n "$(THRIFT_CARGO_SRC)" ] || { \
		echo "Error: could not locate thrift git source via cargo metadata."; \
		echo "Run 'cargo fetch' first."; exit 1; }
	@echo "Building thrift compiler from Cargo source: $(THRIFT_CARGO_SRC)"
	@mkdir -p $(dir $@)
	@BISON=$$(command -v bison 2>/dev/null); \
	 BISON_OPT=$$(brew --prefix bison 2>/dev/null)/bin/bison; \
	 [ -x "$$BISON_OPT" ] && BISON=$$BISON_OPT; \
	 cmake -S $(THRIFT_CARGO_SRC)/compiler/cpp \
	       -B $(CURDIR)/.thrift-compiler/cmake \
	       -DCMAKE_BUILD_TYPE=Release \
	       -DBUILD_TESTING=OFF \
	       -DBISON_EXECUTABLE=$$BISON \
	       -DCMAKE_INSTALL_PREFIX=$(dir $(THRIFT_COMPILER_CACHE)) \
	       > $(CURDIR)/.thrift-compiler/cmake.log 2>&1 \
	 && make -C $(CURDIR)/.thrift-compiler/cmake \
	         -j$$(nproc 2>/dev/null || sysctl -n hw.logicalcpu) \
	         >> $(CURDIR)/.thrift-compiler/cmake.log 2>&1 \
	 && cp $(CURDIR)/.thrift-compiler/cmake/bin/thrift $@ \
	 || { echo "Build failed. See .thrift-compiler/cmake.log"; exit 1; }
	@echo "Thrift compiler built: $@"

codegen: $(THRIFT_COMPILER_CACHE)
	$(THRIFT_COMPILER_CACHE) --gen 'rs:crate_prefix=super' -out crates/core/src/thrift thrift/trees.thrift
	@echo "Generated thrift/trees.rs"
	$(THRIFT_COMPILER_CACHE) --gen 'rs:crate_prefix=super' -out crates/core/src/thrift thrift/event.thrift
	@echo "Generated thrift/event.rs"
	$(THRIFT_COMPILER_CACHE) --gen 'rs:crate_prefix=super' -out crates/core/src/thrift thrift/product.thrift
	@echo "Generated thrift/product.rs"

# Generate documentation
doc:
	cargo doc --workspace --no-deps --open

# Clean build artifacts
clean:
	cargo clean
	rm -rf .thrift-compiler

# Build .NET native library (cdylib)
dotnet-build:
	cargo build -p chat-xdk-dotnet --release

# Build JVM bindings tests — requires JDK 17+ and Maven on PATH.
# Builds the same native cdylib as .NET (`chat_xdk_dotnet`) then runs JUnit via Maven.
jvm-test: dotnet-build
	cd crates/jvm/java/chatxdk && mvn test -Djna.library.path="$(CURDIR)/target/release"

# Build .NET native library and run C# tests.
# The native lib must sit next to the test assembly at runtime: build first,
# stage the lib into the output dir, then run without rebuilding.
dotnet-test: dotnet-build
	@NATIVE_LIB=$$(ls target/release/libchat_xdk_dotnet.dylib target/release/libchat_xdk_dotnet.so target/release/libchat_xdk_dotnet.dll 2>/dev/null | head -1); \
	TEST_PROJ=crates/dotnet/dotnet/ChatXdk.Tests/ChatXdk.Tests.csproj; \
	TEST_DIR=crates/dotnet/dotnet/ChatXdk.Tests/bin/Debug/net8.0; \
	dotnet build "$$TEST_PROJ" && \
	mkdir -p "$$TEST_DIR" && \
	cp "$$NATIVE_LIB" "$$TEST_DIR/" && \
	dotnet test "$$TEST_PROJ" --no-build

# Build Python wheel
wheel:
	cd crates/pyo3 && maturin build --release

# Install Python package locally
wheel-dev:
	cd crates/pyo3 && maturin develop

# Build WebAssembly package.
# The wasm-pack output is copied into crates/wasm/js/pkg/ so the npm package is
# self-contained (npm cannot include files outside the package root). The glob
# copy skips dotfiles, deliberately leaving behind wasm-pack's `.gitignore`
# (its `*` pattern would make npm exclude the whole pkg/ directory).
wasm:
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Error: wasm-pack not installed. Run: cargo install wasm-pack"; exit 1; }
	cd crates/wasm && wasm-pack build --target web --release
	rm -rf crates/wasm/js/pkg
	mkdir -p crates/wasm/js/pkg
	cp crates/wasm/pkg/* crates/wasm/js/pkg/

# Build WebAssembly for Node.js
wasm-node:
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Error: wasm-pack not installed. Run: cargo install wasm-pack"; exit 1; }
	cd crates/wasm && wasm-pack build --target nodejs --release

# Build WebAssembly for bundlers (webpack, etc.)
wasm-bundler:
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Error: wasm-pack not installed. Run: cargo install wasm-pack"; exit 1; }
	cd crates/wasm && wasm-pack build --target bundler --release

# Full CI check (format, lint, Rust workspace tests).
# .github/workflows/ci.yml additionally runs the binding suites: Python, JS/WASM,
# Go (`make test-sdks` covers those; JS needs `make wasm` and Python needs the
# built `_native` extension first) plus JVM (`make jvm-test`) and .NET
# (`make dotnet-test`), and `cargo deny check licenses`.
ci: fmt-check lint license-check test

# Third-party license policy (deny.toml). Requires: cargo install cargo-deny
license-check:
	@command -v cargo-deny >/dev/null 2>&1 || { echo "Error: cargo-deny not installed. Run: cargo install cargo-deny"; exit 1; }
	cargo deny check licenses

# Help
help:
	@echo "chat-xdk build targets:"
	@echo ""
	@echo "  make build        - Build all crates (debug)"
	@echo "  make release      - Build all crates (release)"
	@echo "  make test         - Run all tests"
	@echo "  make check        - Check compilation"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Run clippy"
	@echo "  make license-check - cargo deny check licenses"
	@echo "  make codegen      - Generate types from thrift schemas"
	@echo "  make doc          - Generate and open documentation"
	@echo "  make clean        - Clean build artifacts"
	@echo ""
	@echo "  Language bindings:"
	@echo "  make wheel        - Build Python wheel"
	@echo "  make wheel-dev    - Install Python package locally"
	@echo "  make wasm         - Build WebAssembly for web browsers"
	@echo "  make wasm-node    - Build WebAssembly for Node.js"
	@echo "  make wasm-bundler - Build WebAssembly for bundlers (webpack)"
	@echo "  make go-lib       - Build Go static library"
	@echo "  make prebuilt            - Build and copy .a to libs/<os>_<arch>/ (commit after)"
	@echo "  make prebuilt-linux-amd64 - Cross-compile for Linux amd64 glibc from macOS (needs zig)"
	@echo "  make prebuilt-linux-amd64-musl - Cross-compile for Linux amd64 musl/Alpine from macOS (needs zig)"
	@echo "  make prebuilt-all        - Regenerate all prebuilt binaries (native + linux amd64 glibc + musl)"
	@echo "  make test-go      - Run Go binding tests"
	@echo "  make dotnet-build - Build .NET native library (cdylib)"
	@echo "  make dotnet-test  - Build .NET library and run C# tests"
	@echo "  make jvm-test     - Build cdylib + run JVM (JNA) tests (JDK 17+, Maven)"
	@echo ""
	@echo "  make ci           - Run full CI checks"
	@echo "  make help         - Show this help"
