#ifndef WATCHU_PID_FILTER_H
#define WATCHU_PID_FILTER_H

#include "common.h"
#include "bpf_helpers.h"

#define PID_FILTER_SENTINEL_KEY 0
#define PID_FILTER_MAX_ENTRIES 65536
#define PID_FILTER_MAP_FLAGS 1 // BPF_F_NO_PREALLOC

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PID_FILTER_MAX_ENTRIES);
    __uint(map_flags, PID_FILTER_MAP_FLAGS);
    __type(key, u32);
    __type(value, u8);
} tracked_pids SEC(".maps");

static __always_inline int pid_filter_enabled(void) {
    u32 key = PID_FILTER_SENTINEL_KEY;
    return bpf_map_lookup_elem(&tracked_pids, &key) != NULL;
}

static __always_inline int pid_filter_contains(u32 pid) {
    if (pid == PID_FILTER_SENTINEL_KEY)
        return 0;
    return bpf_map_lookup_elem(&tracked_pids, &pid) != NULL;
}

static __always_inline int should_trace_pid(u32 pid) {
    if (!pid_filter_enabled())
        return 1;
    return pid_filter_contains(pid);
}

static __always_inline int should_trace_pid_tgid(u64 pid_tgid) {
    return should_trace_pid((u32)(pid_tgid >> 32));
}

static __always_inline int should_trace_current_pid(void) {
    return should_trace_pid_tgid(bpf_get_current_pid_tgid());
}

static __always_inline void pid_filter_track(u32 pid) {
    if (pid == PID_FILTER_SENTINEL_KEY)
        return;

    u8 tracked = 1;
    bpf_map_update_elem(&tracked_pids, &pid, &tracked, BPF_ANY);
}

static __always_inline void pid_filter_untrack(u32 pid) {
    if (pid == PID_FILTER_SENTINEL_KEY)
        return;

    bpf_map_delete_elem(&tracked_pids, &pid);
}

#endif
