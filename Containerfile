FROM envoyproxy/envoy:debug-v1.33-latest

ARG WASM_TARGET=wasm32-unknown-unknown

RUN mkdir -p /etc/envoy/

COPY config/envoy.yaml /etc/envoy/envoy.yaml

COPY target/${WASM_TARGET}/release/portkullis_firewall_wasm_module.wasm /etc/envoy/portkullis_firewall.wasm

RUN chown -R envoy /etc/envoy
