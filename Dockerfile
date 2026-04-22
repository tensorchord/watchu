FROM ghcr.io/tensorchord/ebpf-builder:0.2.0 AS builder

WORKDIR /workspace
COPY . .
RUN make build

FROM gcr.io/distroless/static-debian12
COPY --from=builder /workspace/bin/app /usr/local/bin/watchu
ENTRYPOINT ["/usr/local/bin/watchu"]
