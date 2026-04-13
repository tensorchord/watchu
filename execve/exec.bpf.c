//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define LIBSSL_LEN 6
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 2048
#define MAX_ENTRIES 4096
#define RING_BUFFER_SIZE (4 * 1024 * 1024) // 4 MiB

char __license[] SEC("license") = "Dual MIT/GPL";

typedef s32 pid_t;

struct mm_struct {
    unsigned long arg_start;
    unsigned long arg_end;
} __attribute__((preserve_access_index));

struct task_struct {
    struct task_struct *real_parent;
    struct mm_struct *mm;
    pid_t tgid;
    u64 start_boottime;
    u64 start_time;
} __attribute__((preserve_access_index));

// ref: /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
struct sched_process_ctx {
    // pad the first 8 bytes
    long common;
    u32 filename; // __data_loc char * (lower 16 bits: offset, upper 16 bits:
                  // size)
    s32 pid;
    s32 old_pid;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat2/format
struct openat_ctx {
    // pad the first 8 bytes
    long common;
    long __syscall_nr;
    u64 _dfd; // dir fd, used when the filename is a relative path
    u64 filename;
    u64 _flags; // or `how` in openat2
    u64 _mode; // or `usize` in openat2
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/format
// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat2/format
struct openat_exit_ctx {
    // pad the first 8 bytes
    long common;
    long __syscall_nr;
    long ret; // >= 0 means a valid fd, < 0 means error code
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_close/format
struct close_ctx {
    // pad the first 8 bytes
    long common;
    long __syscall_nr;
    u64 fd;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
struct mmap_ctx {
    // pad the first 8 bytes
    long common;
    long __syscall_nr;
    u64 addr;
    u64 length;
    u64 prot;
    u64 flags;
    u64 fd;
    u64 offset;
};

// this is more accurate since one process can match multiple libssl files
// but they won't have the same fd
struct open_key {
    long fd;
    u64 pid_tgid;
};

struct open_value {
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct open_value);
} inflight_open SEC(".maps");

struct proc {
    u64 timestamp_ns;
    u64 start_time_ns;
    u64 parent_start_time_ns;
    s32 pid;
    s32 ppid;
    s32 old_pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    u32 args_len;
    u8 args_truncated;
};

struct exec_value {
    struct proc proc;
    char args[MAX_ARGS_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct exec_value);
} exec_heap SEC(".maps");

// Technically, we should `delete` on both `sys_enter_close` &
// `sched_process_exit`. However, we don't have the `fd` info in
// `sched_process_exit`. Thus we use the LRU hash table to avoid the potential
// memory leak.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct open_key);
    __type(value, struct open_value);
} inflight_mmap SEC(".maps");

// used to make the bpf2go generate proc struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct proc);
} _fake_proc_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} proc_events SEC(".maps");

struct dynlib {
    u64 fd;
    u64 pid_tgid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

// used to make the bpf2go generate dynlib struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dynlib);
} _fake_dynlib_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} dynlib_events SEC(".maps");

static __always_inline u64 read_task_start_time(struct task_struct *task) {
    if (task == NULL)
        return 0;
    if (bpf_core_field_exists(task->start_boottime))
        return BPF_CORE_READ(task, start_boottime);
    return BPF_CORE_READ(task, start_time);
}

static __always_inline void read_exec_args(struct exec_value *value) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (task == NULL)
        return;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm == NULL)
        return;

    unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
    unsigned long arg_end   = BPF_CORE_READ(mm, arg_end);
    if (arg_end <= arg_start)
        return;

    u64 raw_args_len = arg_end - arg_start;
    if (raw_args_len > MAX_ARGS_LEN) {
        raw_args_len               = MAX_ARGS_LEN;
        value->proc.args_truncated = 1;
    }

    u32 args_len = raw_args_len;
    if (args_len == 0)
        return;
    if (bpf_probe_read_user(value->args, args_len, (const void *)arg_start) < 0) {
        value->proc.args_truncated = 1;
        return;
    }
    value->proc.args_len = args_len;
}

SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(struct sched_process_ctx *ctx) {
    if (ctx->pid == 0)
        return 0;

    u32 zero = 0;
    // using this trick needs to care about the stale data
    struct exec_value *value = bpf_map_lookup_elem(&exec_heap, &zero);
    if (value == NULL)
        return 0;

    struct task_struct *task        = bpf_get_current_task_btf();
    struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);

    value->proc.args_len             = 0;
    value->proc.args_truncated       = 0;
    value->proc.timestamp_ns         = bpf_ktime_get_ns();
    value->proc.start_time_ns        = read_task_start_time(task);
    value->proc.parent_start_time_ns = read_task_start_time(parent_task);
    value->proc.pid                  = ctx->pid;
    value->proc.ppid                 = parent_task ? BPF_CORE_READ(parent_task, tgid) : 0;
    value->proc.old_pid              = ctx->old_pid;
    bpf_get_current_comm(&value->proc.comm, TASK_COMM_LEN);

    u32 length = ctx->filename >> 16;
    if (length > MAX_FILENAME_LEN)
        length = MAX_FILENAME_LEN;
    char *filename_ptr = (char *)((void *)ctx + (ctx->filename & 0xFFFF));
    bpf_probe_read_str(&value->proc.filename, length, filename_ptr);

    read_exec_args(value);

    u32 args_len = value->proc.args_len;
    if (args_len > MAX_ARGS_LEN)
        return 0;
    u32 evt_len = sizeof(value->proc) + args_len;
    bpf_ringbuf_output(&proc_events, value, evt_len, 0);
    return 0;
}

static __always_inline int is_libssl(const char *name) {
    int base = 0;
#pragma unroll
    for (int i = 0; i < MAX_FILENAME_LEN; i++) {
        char c = name[i];
        if (c == '\0')
            break;
        if (c == '/')
            base = i + 1;
    }
    if (base + LIBSSL_LEN > MAX_FILENAME_LEN)
        return 0;
    return name[base] == 'l' && name[base + 1] == 'i' && name[base + 2] == 'b' && name[base + 3] == 's' &&
           name[base + 4] == 's' && name[base + 5] == 'l';
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct openat_ctx *ctx) {
    struct open_value ov = {.filename = {}};
    int length           = bpf_probe_read_user_str(ov.filename, MAX_FILENAME_LEN, (void *)ctx->filename);
    if (length <= 0)
        return 0;
    if (is_libssl(ov.filename) == 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&inflight_open, &pid_tgid, &ov, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_sys_exit_openat(struct openat_exit_ctx *ctx) {
    u64 pid_tgid          = bpf_get_current_pid_tgid();
    struct open_value *ov = bpf_map_lookup_elem(&inflight_open, &pid_tgid);
    if (ov == NULL)
        return 0;
    if (ctx->ret < 0)
        goto cleanup;

    struct open_key key = {
        .fd       = ctx->ret,
        .pid_tgid = pid_tgid,
    };
    bpf_map_update_elem(&inflight_mmap, &key, ov, BPF_ANY);

cleanup:
    bpf_map_delete_elem(&inflight_open, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint_sys_enter_mmap(struct mmap_ctx *ctx) {
    struct open_key key = {
        .fd       = ctx->fd,
        .pid_tgid = bpf_get_current_pid_tgid(),
    };
    struct open_value *ov = bpf_map_lookup_elem(&inflight_mmap, &key);
    if (ov == NULL)
        return 0;

    struct dynlib *evt = bpf_ringbuf_reserve(&dynlib_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->fd       = ctx->fd;
    evt->pid_tgid = key.pid_tgid;
    bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
    __builtin_memcpy(evt->filename, ov->filename, sizeof(evt->filename));
    bpf_ringbuf_submit(evt, 0);

    // delete immediately, we don't need duplicate events for the same filename +
    // fd
    bpf_map_delete_elem(&inflight_mmap, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_sys_enter_close(struct close_ctx *ctx) {
    struct open_key key = {
        .fd       = ctx->fd,
        .pid_tgid = bpf_get_current_pid_tgid(),
    };
    bpf_map_delete_elem(&inflight_mmap, &key);
    return 0;
}
