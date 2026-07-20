# Run the offline tests for the chat-xdk examples.
#
#   make test-all        # every example whose toolchain is installed
#   make test-rust       # one example
#
# Offline tests need no credentials. The live e2e (receive -> reply -> send
# against the real X API) is gated behind CHATXDK_E2E=1 and is not run here.

REPO     := $(abspath ..)
PYO3_PKG := $(REPO)/crates/pyo3/python
JAVA17   := $(shell /usr/libexec/java_home -v 17+ 2>/dev/null)

.PHONY: test-all test-rust test-go test-js test-python test-dotnet test-jvm build-python help

test-all: test-rust test-go test-js test-python test-dotnet test-jvm ## Run all available example tests

test-rust: ## Rust (builds chat-xdk-core from source)
	@echo "== rust ==" && cd rust && cargo test

test-go: ## Go (uses the committed libchat_xdk_go.a)
	@echo "== go ==" && cd go && CGO_ENABLED=1 go test ./...

test-js: ## JavaScript / WASM (needs crates/wasm/pkg — build with `cd js && npm run build:wasm`)
	@echo "== js ==" && cd js && node --test

test-python: ## Python (needs the chat_xdk extension; run `make build-python` first)
	@echo "== python ==" && cd python && PYTHONPATH=$(PYO3_PKG):. python3 -m unittest discover -s tests

build-python: ## Build the Python extension into the in-repo package (needs maturin + a venv)
	cd $(REPO)/crates/pyo3 && python3 -m maturin develop

test-dotnet: ## .NET (needs the .NET SDK; builds the native chat_xdk_dotnet lib)
	@command -v dotnet >/dev/null 2>&1 || { echo "== dotnet == (skipped: dotnet not installed)"; exit 0; }
	@echo "== dotnet =="
	cd $(REPO) && cargo build -p chat-xdk-dotnet --release
	cd dotnet && dotnet build ChatBot.Tests/ChatBot.Tests.csproj
	cp $(REPO)/target/release/libchat_xdk_dotnet.dylib dotnet/ChatBot.Tests/bin/Debug/net8.0/ 2>/dev/null || \
		cp $(REPO)/target/release/libchat_xdk_dotnet.so dotnet/ChatBot.Tests/bin/Debug/net8.0/ 2>/dev/null || true
	cd dotnet && DOTNET_ROLL_FORWARD=Major dotnet test ChatBot.Tests/ChatBot.Tests.csproj --no-build

test-jvm: ## JVM (needs JDK 17+ and Maven; builds the native chat_xdk_dotnet lib)
	@command -v mvn >/dev/null 2>&1 || { echo "== jvm == (skipped: maven not installed)"; exit 0; }
	@echo "== jvm =="
	cd $(REPO) && cargo build -p chat-xdk-dotnet --release
	cd $(REPO)/crates/jvm/java/chatxdk && JAVA_HOME=$(JAVA17) mvn -q -DskipTests install
	cd jvm && JAVA_HOME=$(JAVA17) mvn -q test

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
