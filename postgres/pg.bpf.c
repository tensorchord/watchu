//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "vm_used.h"

#define TASK_COMM_LEN 16
#define MAX_LOOP 64
#define MAX_ENTRIES 10240
#define MAX_BUF_SIZE (16 * 1024) // 16 KiB
#define RING_BUFFER_SIZE (32 * 1024 * 1024) // 32 MiB

char __license[] SEC("license") = "Dual MIT/GPL";

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_sendto/format
struct sendto_ctx {
    // padding
    long __common;
    long __syscall_nr;
    u64 fd;
    const void *buf;
    u64 size;
    u64 flags;
    const void *addr; // sockaddr, ignored
    u64 addr_len;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_close/format
struct close_ctx {
    // padding
    long __common;
    long __syscall_nr;
    u64 fd;
};

struct conn_key {
    u64 pid_tgid;
    u64 fd;
};

// store the flag in the u8
// ref: https://www.postgresql.org/docs/18/protocol-message-formats.html
// 1: Postgres plaintext 3-2 (196610)
// 2: Postgres SSL 1234-5679 (80877103)
// 3: Postgres GSSENC 1234-5680 (80877104)
// 4: Other
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, u32);
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
    u8 msg_type; // Q, P, B, E, C, X
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

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint_enter_sendto(struct sendto_ctx *ctx) {
    u64 pid_tgid        = bpf_get_current_pid_tgid();
    struct conn_key key = {
        .pid_tgid = pid_tgid,
        .fd       = ctx->fd,
    };
    u32 *flag = bpf_map_lookup_elem(&inflight, &key);
    if (flag == NULL) {
        // detect the Postgres connection startup packet
        if (ctx->size < 8) {
            return 0;
        }
        u32 new_flag = 4;
        u8 pre[8];
        if (bpf_probe_read_user(&pre, sizeof(pre), ctx->buf) < 0) {
            return 0;
        }
        u32 protocol = (pre[4] << 24) | (pre[5] << 16) | (pre[6] << 8) | pre[7];
        if (protocol >> 16 == 3) {
            new_flag = 1;
        } else if (protocol == 80877103) {
            new_flag = 2;
        } else if (protocol == 80877104) {
            new_flag = 3;
        } else {
            new_flag = 4;
        }
        bpf_map_update_elem(&inflight, &key, &new_flag, BPF_ANY);
        return 0;
    }

    // negotiated Postgres connection, could be plaintext
    if (*flag > 3)
        return 0;

    // only capture the plaintext Postgres traffic
    u64 total_length = ctx->size;
    void *buf        = (void *)ctx->buf;
    u64 ns           = bpf_ktime_get_ns();
    u64 uid_gid      = bpf_get_current_uid_gid();
    u64 cgroup_id    = bpf_get_current_cgroup_id();
    bpf_repeat(MAX_LOOP) {
        if (total_length < 5)
            break;
        u8 hdr[5];
        if (bpf_probe_read_user(&hdr, sizeof(hdr), buf) < 0) {
            return 0;
        }
        u8 tag     = hdr[0];
        u32 length = ((hdr[1] << 24) | (hdr[2] << 16) | (hdr[3] << 8) | hdr[4]) - 4;
        if (length > MAX_BUF_SIZE)
            length = MAX_BUF_SIZE;
        if (length == 0)
            return 0;
        if (length + 5 > total_length)
            // incomplete message, ignore
            return 0;
        // Q, P, B, E, C, X
        if (tag == 0x51 || tag == 0x50 || tag == 0x42 || tag == 0x45 || tag == 0x43 || tag == 0x58) {
            u8 *addr = (u8 *)buf + 5;

            struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
            if (!evt)
                return 0;

            evt->timestamp_ns = ns;
            evt->pid_tgid     = pid_tgid;
            evt->uid_gid      = uid_gid;
            evt->cgroup_id    = cgroup_id;
            evt->req_len      = total_length;
            evt->data_len     = length;
            evt->fd           = ctx->fd;
            evt->msg_type     = tag;
            bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
            bpf_probe_read_user(evt->data, length, (void *)addr);

            bpf_ringbuf_submit(evt, 0);
        }
        buf = (u8 *)buf + length + 5;
        total_length -= length + 5;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_enter_close(struct close_ctx *ctx) {
    u64 pid_tgid        = bpf_get_current_pid_tgid();
    struct conn_key key = {
        .pid_tgid = pid_tgid,
        .fd       = ctx->fd,
    };
    u32 *flag = bpf_map_lookup_elem(&inflight, &key);
    if (flag != NULL) {
        bpf_map_delete_elem(&inflight, &key);
    }
    return 0;
}