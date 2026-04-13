//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16
#define MAX_ENTRIES 16384
#define RING_BUFFER_SIZE (4 * 1024 * 1024)
#define BPF_TCP_ESTABLISHED 1
#define BPF_TCP_SYN_SENT 2

char __license[] SEC("license") = "Dual MIT/GPL";

struct in6_addr {
    union {
        u8 u6_addr8[16];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
    __be16 skc_dport;
    u16 skc_num;
    unsigned short skc_family;
    u8 skc_state;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct event {
    u64 timestamp_ns;
    u64 pid_tgid;
    u64 uid_gid;
    u64 cgroup_id;
    u16 family;
    u16 dport;
    char comm[TASK_COMM_LEN];
    u8 daddr[16];
};

struct connect_meta {
    u64 pid_tgid;
    u64 uid_gid;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct connect_meta);
} inflight_connect SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

static __always_inline int remember_connect(struct sock *sk) {
    u64 key                   = (u64)sk;
    struct connect_meta value = {};

    if (!sk) {
        return 0;
    }

    // tcp_set_state can execute later in softirq/kernel context, where current
    // pid/comm may be swapper/* instead of the userspace task that initiated
    // the connect. Capture attribution here in tcp_v{4,6}_connect while we are
    // still running in the calling task context, then join it later by socket.
    value.pid_tgid  = bpf_get_current_pid_tgid();
    value.uid_gid   = bpf_get_current_uid_gid();
    value.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&value.comm, sizeof(value.comm));

    bpf_map_update_elem(&inflight_connect, &key, &value, BPF_ANY);
    return 0;
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(trace_tcp_v4_connect, struct sock *sk) {
    return remember_connect(sk);
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(trace_tcp_v6_connect, struct sock *sk) {
    return remember_connect(sk);
}

SEC("fentry/tcp_close")
int BPF_PROG(trace_tcp_close, struct sock *sk) {
    u64 key = (u64)sk;

    if (!sk) {
        return 0;
    }

    bpf_map_delete_elem(&inflight_connect, &key);
    return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(trace_tcp_set_state, struct sock *sk, int state) {
    u64 key = (u64)sk;

    if (!sk) {
        return 0;
    }
    struct connect_meta *meta = bpf_map_lookup_elem(&inflight_connect, &key);
    if (!meta) {
        return 0;
    }

    if (state != BPF_TCP_ESTABLISHED) {
        if (BPF_CORE_READ(sk, __sk_common.skc_state) == BPF_TCP_SYN_SENT) {
            bpf_map_delete_elem(&inflight_connect, &key);
        }
        return 0;
    }

    if (BPF_CORE_READ(sk, __sk_common.skc_state) != BPF_TCP_SYN_SENT) {
        return 0;
    }

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&inflight_connect, &key);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = meta->pid_tgid;
    evt->uid_gid      = meta->uid_gid;
    evt->cgroup_id    = meta->cgroup_id;
    evt->family       = family;
    evt->dport        = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __builtin_memcpy(evt->comm, meta->comm, sizeof(evt->comm));

    if (family == AF_INET) {
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(evt->daddr, &daddr, sizeof(daddr));
    } else {
        BPF_CORE_READ_INTO(&evt->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&inflight_connect, &key);
    return 0;
}
