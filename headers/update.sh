#!/usr/bin/env bash

LIBBPF_VERSION=1.7.0

PREFIX=libbpf-${LIBBPF_VERSION}
HEADERS=(
    ${PREFIX}/LICENSE.BSD-2-Clause
    ${PREFIX}/src/bpf.h
    ${PREFIX}/src/bpf_endian.h
    ${PREFIX}/src/bpf_helper_defs.h
    ${PREFIX}/src/bpf_helpers.h
    ${PREFIX}/src/bpf_tracing.h
    ${PREFIX}/src/bpf_core_read.h
)

curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar -xz --xform='s#.*/##' "${HEADERS[@]}"
