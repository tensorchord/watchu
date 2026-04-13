//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "vm_used.h"

#include "ssl_common.h"

struct call_info {
    u64 buf_addr;
    u64 len;
    u64 ssl_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct call_info);
} start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

// used to make the bpf2go generate event struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} _fake_event_map SEC(".maps");

SEC("uprobe/boring_ssl_read_entry")
int probe_boring_ssl_read_entry(struct pt_regs *ctx) {
    struct call_info info = {};
    u64 key               = bpf_get_current_pid_tgid();
    info.ssl_ptr          = (u64)PT_REGS_PARM1(ctx);
    info.buf_addr         = (u64)PT_REGS_PARM2(ctx);
    info.len              = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&start_map, &key, &info, BPF_ANY);
    return 0;
};

SEC("uretprobe/boring_ssl_read_exit")
int probe_boring_ssl_read_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&start_map, &key);
    if (info == NULL)
        return 0;

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    u64 now       = bpf_ktime_get_ns();
    u64 uid_gid   = bpf_get_current_uid_gid();
    u64 cgroup_id = bpf_get_current_cgroup_id();
    void *buf     = (void *)info->buf_addr;

    bpf_repeat(MAX_LOOP) {
        u32 length = (u32)ret; // Cast is safe: ret > 0 guaranteed by guard above
        if (length == 0)
            break;
        if (length > MAX_BODY_SIZE)
            length = MAX_BODY_SIZE;

        struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) {
            // retry in the next loop, but still limited to MAX_LOOP
            continue;
        }

        evt->pid_tgid     = key;
        evt->ssl_ptr      = info->ssl_ptr;
        evt->uid_gid      = uid_gid;
        evt->cgroup_id    = cgroup_id;
        evt->timestamp_ns = now;
        evt->req_len      = info->len;
        evt->data_len     = length;
        evt->rw           = 4;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);

        bpf_ringbuf_submit(evt, 0);
        buf = (u8 *)buf + length;
        ret -= length;
    }

cleanup:
    bpf_map_delete_elem(&start_map, &key);
    return 0;
}

SEC("uretprobe/boring_ssl_write_exit")
int probe_boring_ssl_write_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&start_map, &key);
    if (info == NULL)
        return 0;

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    u64 now       = bpf_ktime_get_ns();
    u64 uid_gid   = bpf_get_current_uid_gid();
    u64 cgroup_id = bpf_get_current_cgroup_id();
    void *buf     = (void *)info->buf_addr;

    bpf_repeat(MAX_LOOP) {
        u32 length = (u32)ret;
        if (length == 0)
            break;
        if (length > MAX_BODY_SIZE)
            length = MAX_BODY_SIZE;

        struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) {
            // retry in the next loop, but still limited to MAX_LOOP
            continue;
        }

        evt->pid_tgid     = key;
        evt->uid_gid      = uid_gid;
        evt->cgroup_id    = cgroup_id;
        evt->ssl_ptr      = info->ssl_ptr;
        evt->timestamp_ns = now;
        evt->req_len      = info->len;
        evt->data_len     = length;
        evt->rw           = 2;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);

        bpf_ringbuf_submit(evt, 0);
        buf = (u8 *)buf + length;
        ret -= length;
    }

cleanup:
    bpf_map_delete_elem(&start_map, &key);
    return 0;
}
