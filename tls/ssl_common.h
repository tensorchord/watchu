#include "common.h"

#define MAX_BODY_SIZE (64 * 1024) // 64 KiB
#define RING_BUFFER_SIZE (32 * 1024 * 1024) // 32 MiB
#define MAX_LOOP 64 // make it 64 * 64 = 4096KiB = 4MiB
#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct call_info {
    u64 buf_addr;
    u64 len;
    u64 ssl_ptr;
};

struct call_info_ex {
    struct call_info base;
    u64 consumed_len_ptr;
};

struct event {
    u64 timestamp_ns;
    u64 pid_tgid;
    u64 uid_gid;
    u64 cgroup_id;
    u64 ssl_ptr;
    u64 req_len;
    u64 data_len;
    u8 rw; // rwx: 2 write, 4 read
    char comm[TASK_COMM_LEN];
    u8 data[MAX_BODY_SIZE];
};

static __always_inline struct call_info new_call_info(struct pt_regs *ctx) {
    return (struct call_info){
        .ssl_ptr  = (u64)PT_REGS_PARM1(ctx),
        .buf_addr = (u64)PT_REGS_PARM2(ctx),
        .len      = (int)PT_REGS_PARM3(ctx),
    };
}

static __always_inline struct call_info_ex new_call_info_ex(struct pt_regs *ctx) {
    return (struct call_info_ex){
        .base =
            {
                .ssl_ptr  = (u64)PT_REGS_PARM1(ctx),
                .buf_addr = (u64)PT_REGS_PARM2(ctx),
                .len      = (int)PT_REGS_PARM3(ctx),
            },
        .consumed_len_ptr = (u64)PT_REGS_PARM4(ctx),
    };
}

static __always_inline void emit_ssl_events(void *ringbuf, u64 key, const struct call_info *info, size_t remaining, u8 rw) {
    u64 now       = bpf_ktime_get_ns();
    u64 uid_gid   = bpf_get_current_uid_gid();
    u64 cgroup_id = bpf_get_current_cgroup_id();
    void *buf     = (void *)info->buf_addr;
    size_t max_bytes = MAX_LOOP * MAX_BODY_SIZE;

    if (remaining > max_bytes)
        remaining = max_bytes;

    bpf_repeat(MAX_LOOP) {
        u32 length = (u32)remaining;
        if (length == 0)
            break;
        if (length > MAX_BODY_SIZE)
            length = MAX_BODY_SIZE;

        struct event *evt = bpf_ringbuf_reserve(ringbuf, sizeof(*evt), 0);
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
        evt->rw           = rw;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);

        bpf_ringbuf_submit(evt, 0);
        buf = (u8 *)buf + length;
        remaining -= length;
    }
}

char __license[] SEC("license") = "Dual BSD/GPL";
