# syntax=docker/dockerfile:1.7
# The container of the FUSE test of the volumes: weed mount (the pinned SeaweedFS release of test/seaweedfs), FUSE 3,
# the pinned Rust image for the tests of the volumes on the mount, and Stowr. compose.yaml gives this container
# /dev/fuse and SYS_ADMIN for the mount. No other container of the tests has them.
# The image builds Stowr and the tests with the profile of `cargo test`: the two builds share the compiled crates.
# The image stays on the machine of the tests. No script of this repository pushes it to a registry.
ARG RUST_IMAGE=rust:1.99.1-trixie
FROM ${RUST_IMAGE}

ARG TARGETARCH
ARG SEAWEEDFS_VERSION=4.41
ARG SEAWEEDFS_LINUX_AMD64_SHA256=730f1ede19972c12954ee407b2d97679a2e4486d24fd987d371761ec395571b8
ARG SEAWEEDFS_LINUX_ARM64_SHA256=ecfb79fb8e0f235ea537948c9ea6041cec87c545746d369bf1f10e3ca10aa186

RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends fuse3; \
    rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH:-amd64}" in \
      amd64) sha="$SEAWEEDFS_LINUX_AMD64_SHA256" ;; \
      arm64) sha="$SEAWEEDFS_LINUX_ARM64_SHA256" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    wget -q -O /tmp/weed.tgz "https://github.com/seaweedfs/seaweedfs/releases/download/${SEAWEEDFS_VERSION}/linux_${TARGETARCH:-amd64}.tar.gz"; \
    echo "${sha}  /tmp/weed.tgz" | sha256sum -c -; \
    tar -xzf /tmp/weed.tgz -C /usr/local/bin weed; \
    chmod +x /usr/local/bin/weed; \
    rm -f /tmp/weed.tgz

WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
# run.sh runs `cargo test --locked --offline volume::` in this folder: the crates and the test files are in the image.
RUN set -eu; \
    cargo build --locked; \
    install -m 0755 target/debug/stowr /usr/local/bin/stowr; \
    cargo test --locked --no-run; \
    stowr version

COPY test/volume-fuse/scripts/entrypoint.sh /bin/entrypoint.sh
ENTRYPOINT ["/bin/sh", "/bin/entrypoint.sh"]
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=20 \
  CMD ["/usr/local/bin/stowr", "healthcheck", "-c", "/config/config.hcl"]
