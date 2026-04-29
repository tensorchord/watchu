//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "vm_used.h"

#include "ssl_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct call_info);
} start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct call_info_ex);
} start_ex_map SEC(".maps");

// used to make the bpf2go generate event struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} _fake_event_map SEC(".maps");

SEC("uprobe/ssl_read_entry")
int probe_ssl_read_entry(struct pt_regs *ctx) {
    struct call_info info = new_call_info(ctx);
    u64 key               = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&start_map, &key, &info, BPF_ANY);
    return 0;
};

SEC("uprobe/ssl_write_entry")
int probe_ssl_write_entry(struct pt_regs *ctx) {
    struct call_info info = new_call_info(ctx);
    u64 key               = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&start_map, &key, &info, BPF_ANY);
    return 0;
};

SEC("uprobe/ssl_read_ex_entry")
int probe_ssl_read_ex_entry(struct pt_regs *ctx) {
    struct call_info_ex info = new_call_info_ex(ctx);
    u64 key                  = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&start_ex_map, &key, &info, BPF_ANY);
    return 0;
};

SEC("uprobe/ssl_write_ex_entry")
int probe_ssl_write_ex_entry(struct pt_regs *ctx) {
    struct call_info_ex info = new_call_info_ex(ctx);
    u64 key                  = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&start_ex_map, &key, &info, BPF_ANY);
    return 0;
};

SEC("uretprobe/ssl_read_exit")
int probe_ssl_read_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&start_map, &key);
    if (info == NULL)
        return 0;

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    emit_ssl_events(&events, key, info, ret, 4);

cleanup:
    bpf_map_delete_elem(&start_map, &key);
    return 0;
}

SEC("uretprobe/SSL_read_ex_exit")
int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
    u64 key                   = bpf_get_current_pid_tgid();
    struct call_info_ex *info = bpf_map_lookup_elem(&start_ex_map, &key);
    if (info == NULL)
        goto cleanup;

    int ret = PT_REGS_RC(ctx);
    if (ret != 1)
        goto cleanup;

    size_t readbytes = 0;
    bpf_probe_read_user(&readbytes, sizeof(readbytes), (void *)info->consumed_len_ptr);
    emit_ssl_events(&events, key, &info->base, readbytes, 4);

cleanup:
    bpf_map_delete_elem(&start_ex_map, &key);
    return 0;
}

SEC("uretprobe/ssl_write_exit")
int probe_ssl_write_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&start_map, &key);
    if (info == NULL)
        return 0;

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    emit_ssl_events(&events, key, info, ret, 2);

cleanup:
    bpf_map_delete_elem(&start_map, &key);
    return 0;
}

SEC("uretprobe/ssl_write_ex_exit")
int probe_ssl_write_ex_exit(struct pt_regs *ctx) {
    u64 key                   = bpf_get_current_pid_tgid();
    struct call_info_ex *info = bpf_map_lookup_elem(&start_ex_map, &key);
    if (info == NULL)
        goto cleanup;

    int ret = PT_REGS_RC(ctx);
    if (ret != 1)
        goto cleanup;

    size_t written = 0;
    bpf_probe_read_user(&written, sizeof(written), (void *)info->consumed_len_ptr);
    emit_ssl_events(&events, key, &info->base, written, 2);

cleanup:
    bpf_map_delete_elem(&start_ex_map, &key);
    return 0;
}
