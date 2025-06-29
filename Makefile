# ------------------------------------------------------------------------------
# Environment - Build
# ------------------------------------------------------------------------------

CONTAINER_RUNTIME ?= podman
CONTAINER_IMAGE ?= envoy-firewall

# ------------------------------------------------------------------------------
# Environment - WASM
# ------------------------------------------------------------------------------

WASM_MODULE_PACKAGE ?= portkullis-firewall-wasm-module
WASM_TARGET ?= wasm32-unknown-unknown

# ------------------------------------------------------------------------------
# Build Targets
# ------------------------------------------------------------------------------

.PHONY: all
all: build

.PHONY: build
build:
	cargo build --package $(WASM_MODULE_PACKAGE) --target $(WASM_TARGET) --release

.PHONY: build.all_features
build.all_features:
	cargo build --package $(WASM_MODULE_PACKAGE) --target $(WASM_TARGET) --release --all-features

.PHONY: build.image
build.image: build
	$(CONTAINER_RUNTIME) build -t $(CONTAINER_IMAGE) -f Containerfile --build-arg WASM_TARGET=$(WASM_TARGET) .

.PHONY: build.image.all_features
build.image.all_features: build.all_features
	$(CONTAINER_RUNTIME) build -t $(CONTAINER_IMAGE) -f Containerfile --build-arg WASM_TARGET=$(WASM_TARGET) .

# ------------------------------------------------------------------------------
# Test Targets
# ------------------------------------------------------------------------------

.PHONY: test
test:
	cargo test --package signature_detection_engine --package anomaly_detection_engine

.PHONY: test.integration
test.integration: build.image
	cargo test --package $(WASM_MODULE_PACKAGE) --test integration_tests

# ------------------------------------------------------------------------------
# Run Targets
# ------------------------------------------------------------------------------

QDRANT_IMAGE ?= qdrant/qdrant
QDRANT_VERSION ?= v1.14.1

.PHONY: run.envoy
run.envoy: build.image
	$(CONTAINER_RUNTIME) run --rm -it --user 1000 --network host -p 10000:10000 $(CONTAINER_IMAGE)

.PHONY: run.envoy.all_features
run.envoy.all_features: build.image.all_features
	$(CONTAINER_RUNTIME) run --rm -it --user 1000 --network host -p 10000:10000 $(CONTAINER_IMAGE)

.PHONY: run.qdrant
run.qdrant:
	$(CONTAINER_RUNTIME) run --rm -it -p 6333:6333 -p 6334:6334 $(QDRANT_IMAGE):$(QDRANT_VERSION)

.PHONY: run.grpc
run.grpc:
	cargo run --package anomaly_detection_engine --bin anomaly_detection_engine
