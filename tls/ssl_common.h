#include "common.h"

#define MAX_BODY_SIZE (64 * 1024) // 64 KiB
#define RING_BUFFER_SIZE (32 * 1024 * 1024) // 32 MiB
#define MAX_LOOP 64 // make it 64 * 64 = 4096KiB = 4MiB
#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

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

char __license[] SEC("license") = "Dual BSD/GPL";
