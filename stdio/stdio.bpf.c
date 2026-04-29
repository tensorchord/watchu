//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16
#define RING_BUFFER_SIZE (32 * 1024 * 1024) // 32 MiB
#define MAX_BUF_SIZE (128 * 1024) // 128 KiB
#define PEEK_BYTES 4

char __license[] SEC("license") = "Dual MIT/GPL";

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
struct enter_ctx {
    // pad the first 16 bytes
    long common;
    long __syscall_nr;
    u64 fd;
    const char *buf;
    size_t count;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
struct exit_ctx {
    // pad the first 16 bytes
    long common;
    long __syscall_nr;
    long ret;
};

struct inflight_read {
    u64 buf;
    u64 count;
    u64 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct inflight_read);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

struct event {
    u64 timestamp_ns;
    u64 pid_tgid;
    u64 uid_gid;
    u64 req_len;
    u64 cgroup_id;
    u64 data_len;
    u64 fd;
    u8 rw; // rwx: 4 read, 2 write
    u8 data[MAX_BUF_SIZE];
    char comm[TASK_COMM_LEN];
};

// used to make the bpf2go generate event struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} _fake_event_map SEC(".maps");

// this is specific for MCP StdIO JSON
static __always_inline u8 is_mcp_json_str(const char *buf, u32 len) {
    if (len < PEEK_BYTES) {
        return 0;
    }

    char prefix[PEEK_BYTES];
    if (bpf_probe_read(prefix, PEEK_BYTES, buf) != 0) {
        return 0;
    }

#pragma unroll
    for (int i = 0; i < PEEK_BYTES; i++) {
        char c = prefix[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        if (c == '{') {
            return 1;
        }
        break;
    }
    return 0;
}

static __always_inline int emit_stdio_event(const void *buf, u64 req_len, u32 data_len, u64 fd, u8 rw) {
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    evt->req_len      = req_len;
    evt->data_len     = data_len;
    evt->fd           = fd;
    evt->rw           = rw;
    bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
    bpf_probe_read(evt->data, data_len, buf);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_enter_read(struct enter_ctx *ctx) {
    if (ctx->count == 0) {
        return 0;
    }
    // stdin
    if (ctx->fd != 0) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct inflight_read read = {
        .buf   = (u64)ctx->buf,
        .count = ctx->count,
        .fd    = ctx->fd,
    };
    bpf_map_update_elem(&inflight, &pid_tgid, &read, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_exit_read(struct exit_ctx *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ctx->ret < 0)
        goto cleanup;
    u32 length = (u32)ctx->ret;
    if (length == 0)
        goto cleanup;
    if (length > MAX_BUF_SIZE)
        length = MAX_BUF_SIZE;

    struct inflight_read *read = bpf_map_lookup_elem(&inflight, &pid_tgid);
    if (read == NULL)
        goto cleanup;

    if (is_mcp_json_str((const char *)read->buf, length) == 0)
        goto cleanup;

    emit_stdio_event((void *)read->buf, read->count, length, read->fd, 4);

cleanup:
    bpf_map_delete_elem(&inflight, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_enter_write(struct enter_ctx *ctx) {
    if (ctx->count == 0) {
        return 0;
    }
    // stdout
    if (ctx->fd != 1) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();

    u32 length = (u32)ctx->count;
    if (length > MAX_BUF_SIZE)
        length = MAX_BUF_SIZE;

    if (is_mcp_json_str((const char *)ctx->buf, length) == 0)
        return 0;

    return emit_stdio_event((void *)ctx->buf, ctx->count, length, ctx->fd, 2);
}
