#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
set -eu

# The service is healthy when the entrypoint created the buckets and the node reports a healthy cluster.
test -f /tmp/ready
garage json-api GetClusterHealth 2>/dev/null | grep -Eq '"status"[[:space:]]*:[[:space:]]*"healthy"'
