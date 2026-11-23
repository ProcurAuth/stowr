# syntax=docker/dockerfile:1.7
# The image of Stowr for the test stacks: the static binary (musl target) built in the pinned Rust image, on scratch.
# The image stays on the machine of the tests. No script of this repository pushes it to a registry.
# The release archives do not come from this file: refer to .github/workflows/release.yaml.
ARG RUST_IMAGE=rust:1.99.1-trixie
FROM ${RUST_IMAGE} AS builder
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=
# Test stacks only: a lower size from which a copy goes in parts, and a lower part size (in bytes). Empty keeps the
# values of the release build. The build gives them to the program as STOWR_MULTIPART_COPY_THRESHOLD and
# STOWR_MULTIPART_COPY_PART_SIZE.
ARG MULTIPART_COPY_THRESHOLD=
ARG MULTIPART_COPY_PART_SIZE=

# musl-tools compiles the C code of the cryptography library (aws-lc) for the musl target.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends musl-tools ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    rustup target add "$(uname -m)-unknown-linux-musl"

WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/

# The cache mounts keep the crates and the build files between two builds of the test stacks. They are not in the image.
# Two checkouts can share the cache: the touch makes cargo compile the sources of this context again.
RUN --mount=type=cache,id=stowr-test-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=stowr-test-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=stowr-test-target,target=/build/target \
    set -eu; \
    find build.rs src -type f -exec touch {} +; \
    target="$(uname -m)-unknown-linux-musl"; \
    STOWR_BUILD_VERSION="${VERSION}" \
    STOWR_BUILD_COMMIT="${COMMIT}" \
    STOWR_BUILD_DATE="${BUILD_DATE}" \
    STOWR_MULTIPART_COPY_THRESHOLD="${MULTIPART_COPY_THRESHOLD}" \
    STOWR_MULTIPART_COPY_PART_SIZE="${MULTIPART_COPY_PART_SIZE}" \
      cargo build --release --locked --target "$target"; \
    binary="target/$target/release/stowr"; \
    if readelf -l "$binary" | grep -q 'Requesting program interpreter'; then echo "stowr needs a dynamic loader" >&2; exit 1; fi; \
    if readelf -d "$binary" 2>/dev/null | grep -q NEEDED; then echo "stowr needs a shared library" >&2; exit 1; fi; \
    mkdir -p /out/rootfs/config /out/rootfs/etc/ssl/certs; \
    install -m 0755 "$binary" /out/rootfs/stowr; \
    cp /etc/ssl/certs/ca-certificates.crt /out/rootfs/etc/ssl/certs/ca-certificates.crt; \
    /out/rootfs/stowr version

# The runtime contains only the static binary and the CA bundle. The program needs no writable file system, no data
# volume and no /tmp.
FROM scratch AS runtime
COPY --from=builder /out/rootfs/ /
USER 65532:65532
WORKDIR /
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/stowr"]
CMD ["-c", "/config/config.hcl"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/stowr", "healthcheck", "-c", "/config/config.hcl"]
