//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16
#define MAX_PATH_SIZE 256
#define MAX_PREFIX_LEN 36
#define MAX_ENTRIES 16384
#define RING_BUFFER_SIZE (8 * 1024 * 1024)
#define AT_FDCWD -100

#define PROT_WRITE 0x2

char __license[] SEC("license") = "Dual MIT/GPL";

enum file_op_type {
    FILE_OP_OPEN       = 1,
    FILE_OP_WRITE      = 2,
    FILE_OP_DELETE     = 3,
    FILE_OP_RENAME     = 4,
    FILE_OP_MMAP_READ  = 5,
    FILE_OP_MMAP_WRITE = 6,
    FILE_OP_HARDLINK   = 7,
    FILE_OP_SYMLINK    = 8,
};

enum fd_seen_flag {
    FD_SEEN_WRITE      = 1 << 0,
    FD_SEEN_MMAP_READ  = 1 << 1,
    FD_SEEN_MMAP_WRITE = 1 << 2,
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
struct enter_open_ctx {
    long common;
    long __syscall_nr;
    const char *filename;
    int flags;
    u16 mode;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
struct enter_openat_ctx {
    long common;
    long __syscall_nr;
    long dfd;
    const char *filename;
    int flags;
    u16 mode;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat2/format
struct enter_openat2_ctx {
    long common;
    long __syscall_nr;
    long dfd;
    const char *filename;
    const void *how;
    size_t usize;
};

struct open_how {
    u64 flags;
    u64 mode;
    u64 resolve;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_open/format
// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/format
// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat2/format
struct exit_ctx {
    long common;
    long __syscall_nr;
    long ret;
};

// We intentionally do not probe sys_enter_read. Read syscalls are much noisier
// than open, and the allowlist policy is more useful on open/mmap_read than on
// per-read events. mmap_read stays enabled because mapped reads bypass the read
// syscall path entirely.
// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
struct enter_rw_ctx {
    long common;
    long __syscall_nr;
    u64 fd;
    const void *buf;
    size_t count;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
struct enter_mmap_ctx {
    long common;
    long __syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_close/format
struct enter_close_ctx {
    long common;
    long __syscall_nr;
    unsigned int fd;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat/format
struct enter_unlinkat_ctx {
    long common;
    long __syscall_nr;
    long dfd;
    const char *pathname;
    int flag;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_rename/format
struct enter_rename_ctx {
    long common;
    long __syscall_nr;
    const char *oldname;
    const char *newname;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_renameat/format
struct enter_renameat_ctx {
    long common;
    long __syscall_nr;
    long olddfd;
    const char *oldname;
    long newdfd;
    const char *newname;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_renameat2/format
struct enter_renameat2_ctx {
    long common;
    long __syscall_nr;
    long olddfd;
    const char *oldname;
    long newdfd;
    const char *newname;
    unsigned int flags;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_link/format
struct enter_link_ctx {
    long common;
    long __syscall_nr;
    const char *oldname;
    const char *newname;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_linkat/format
struct enter_linkat_ctx {
    long common;
    long __syscall_nr;
    long olddfd;
    const char *oldname;
    long newdfd;
    const char *newname;
    int flags;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_symlink/format
struct enter_symlink_ctx {
    long common;
    long __syscall_nr;
    const char *oldname;
    const char *newname;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_symlinkat/format
struct enter_symlinkat_ctx {
    long common;
    long __syscall_nr;
    const char *oldname;
    long newdfd;
    const char *newname;
};

struct fd_key {
    u32 tgid;
    u32 fd;
};

struct path_value {
    char path[MAX_PATH_SIZE];
    u64 write_bytes;
    u64 open_flags;
    u8 seen_flags;
};

struct event {
    u64 timestamp_ns;
    u64 pid_tgid;
    u64 uid_gid;
    u64 cgroup_id;
    u64 bytes;
    u64 flags;
    u8 op;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_SIZE];
    char new_path[MAX_PATH_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct path_value);
} inflight_open SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u32);
} inflight_write SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, struct path_value);
} path_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct fd_key);
    __type(value, struct path_value);
} fd_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} _fake_event_map SEC(".maps");

static __always_inline int str_has_prefix(const char *s, const char *prefix, int prefix_len) {
#pragma unroll
    for (int i = 0; i < MAX_PREFIX_LEN; i++) {
        if (i >= prefix_len) {
            return 1;
        }
        if (s[i] != prefix[i]) {
            return 0;
        }
    }
    return 0;
}

static __always_inline int path_looks_like_shared_object(const char *path) {
    for (int i = 0; i < MAX_PATH_SIZE - 3; i++) {
        if (path[i] == 0) {
            return 0;
        }
        if (path[i] == '.' && path[i + 1] == 's' && path[i + 2] == 'o' && (path[i + 3] == 0 || path[i + 3] == '.')) {
            return 1;
        }
    }
    return 0;
}

static __noinline int is_noise_path(const char *path) {
    static const char proc_prefix[]    = "/proc/";
    static const char sys_prefix[]     = "/sys/";
    static const char dev_pts_prefix[] = "/dev/pts/";
    static const char dev_shm_prefix[] = "/dev/shm/";
    static const char run_prefix[]     = "/run/";

    if (!path) {
        return 1;
    }
    if (str_has_prefix(path, proc_prefix, sizeof(proc_prefix) - 1)) {
        return 1;
    }
    if (str_has_prefix(path, sys_prefix, sizeof(sys_prefix) - 1)) {
        return 1;
    }
    if (str_has_prefix(path, dev_pts_prefix, sizeof(dev_pts_prefix) - 1)) {
        return 1;
    }
    if (str_has_prefix(path, dev_shm_prefix, sizeof(dev_shm_prefix) - 1)) {
        return 1;
    }
    if (str_has_prefix(path, run_prefix, sizeof(run_prefix) - 1)) {
        return 1;
    }
    return 0;
}

static __always_inline int path_is_runtime_overlay_noise(const char *path) {
    static const char var_lib_prefix[]            = "/var/lib/";
    static const char buildkit_overlay_prefix[]   = "buildkit/runc-overlayfs/";
    static const char docker_overlay_prefix[]     = "docker/overlay2/";
    static const char podman_overlay_prefix[]     = "containers/storage/overlay/";
    static const char containerd_overlay_prefix[] = "containerd/io.containerd.snapshotter";
    const char *subpath;

    if (!path) {
        return 0;
    }
    if (!str_has_prefix(path, var_lib_prefix, sizeof(var_lib_prefix) - 1)) {
        return 0;
    }

    subpath = path + sizeof(var_lib_prefix) - 1;
    if (str_has_prefix(subpath, buildkit_overlay_prefix, sizeof(buildkit_overlay_prefix) - 1)) {
        return 1;
    }
    if (str_has_prefix(subpath, docker_overlay_prefix, sizeof(docker_overlay_prefix) - 1)) {
        return 1;
    }
    if (str_has_prefix(subpath, podman_overlay_prefix, sizeof(podman_overlay_prefix) - 1)) {
        return 1;
    }
    if (str_has_prefix(subpath, containerd_overlay_prefix, sizeof(containerd_overlay_prefix) - 1)) {
        return 1;
    }
    return 0;
}

static __noinline int path_is_systemd_private_tmp_noise(const char *path) {
    static const char tmp_prefix[]     = "/tmp/systemd-private-";
    static const char var_tmp_prefix[] = "/var/tmp/systemd-private-";

    if (!path) {
        return 0;
    }
    if (str_has_prefix(path, tmp_prefix, sizeof(tmp_prefix) - 1)) {
        return 1;
    }
    if (str_has_prefix(path, var_tmp_prefix, sizeof(var_tmp_prefix) - 1)) {
        return 1;
    }
    return 0;
}

static __always_inline int should_drop_fd_event(const struct path_value *path, u8 op) {
    if (!path) {
        return 1;
    }
    if ((op == FILE_OP_MMAP_READ || op == FILE_OP_MMAP_WRITE) && path_looks_like_shared_object(path->path)) {
        return 1;
    }
    if (path_is_runtime_overlay_noise(path->path)) {
        return 1;
    }
    return 0;
}

static __always_inline int copy_user_path(char *dst, u32 size, const char *src) {
    long copied;

    if (!src) {
        return -1;
    }
    copied = bpf_probe_read_user_str(dst, size, src);
    if (copied <= 1) {
        return -1;
    }
    return 0;
}

static __always_inline int is_absolute_path(const char *path) {
    return path && path[0] == '/';
}

static __always_inline int join_paths(char *dst, u32 size, const char *base, const char *relative) {
    int off = 0;

    if (!dst || !base || !relative || size == 0) {
        return -1;
    }

    for (int i = 0; i < MAX_PATH_SIZE; i++) {
        if (off >= (int)size - 1) {
            dst[off] = 0;
            return 0;
        }
        if (base[i] == 0) {
            break;
        }
        dst[off++] = base[i];
    }

    if (off == 0) {
        return -1;
    }
    if (dst[off - 1] != '/' && off < (int)size - 1) {
        dst[off++] = '/';
    }

    for (int i = 0; i < MAX_PATH_SIZE; i++) {
        if (off >= (int)size - 1) {
            break;
        }
        if (relative[i] == 0) {
            break;
        }
        dst[off++] = relative[i];
    }

    dst[off] = 0;
    return 0;
}

static __noinline int resolve_dirfd_path(char *dst, u32 size, u32 tgid, long dirfd, const char *src) {
    struct fd_key key = {};
    struct path_value *base;
    struct path_value *relative;
    u32 scratch_idx = 1;

    if (!src) {
        return -1;
    }
    if (copy_user_path(dst, size, src) != 0) {
        return -1;
    }
    // AT_FDCWD is only a sentinel here. We do not track task cwd in this probe,
    // so relative paths that rely on cwd remain relative in the emitted event.
    if (is_absolute_path(dst) || dirfd == AT_FDCWD || dirfd < 0) {
        return 0;
    }

    relative = bpf_map_lookup_elem(&path_heap, &scratch_idx);
    if (!relative) {
        return 0;
    }
    __builtin_memcpy(relative->path, dst, sizeof(relative->path));

    key.tgid = tgid;
    key.fd   = (u32)dirfd;
    base     = bpf_map_lookup_elem(&fd_paths, &key);
    if (!base) {
        __builtin_memcpy(dst, relative->path, sizeof(relative->path));
        return 0;
    }

    return join_paths(dst, size, base->path, relative->path);
}

static __always_inline int has_seen_flag(const struct path_value *path, u8 flag) {
    return path && (path->seen_flags & flag);
}

static __always_inline void set_seen_flag(struct path_value *path, u8 flag) {
    if (!path) {
        return;
    }
    path->seen_flags |= flag;
}

static __always_inline int submit_fd_event(struct path_value *path, u8 op, u64 bytes) {
    struct event *evt;

    if (should_drop_fd_event(path, op)) {
        return 0;
    }

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    evt->bytes        = bytes;
    evt->flags        = path->open_flags;
    evt->op           = op;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->path, path->path, sizeof(evt->path));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __always_inline int submit_open_event(struct path_value *path) {
    return submit_fd_event(path, FILE_OP_OPEN, 0);
}

static __always_inline int submit_delete_path(const char *path, long dirfd) {
    struct event *evt;
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    evt->bytes        = 0;
    evt->op           = FILE_OP_DELETE;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (resolve_dirfd_path(evt->path, sizeof(evt->path), tgid, dirfd, path) != 0 || is_noise_path(evt->path) ||
        path_is_systemd_private_tmp_noise(evt->path)) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __noinline int submit_rename_paths(const char *old_path, long old_dirfd, const char *new_path) {
    struct event *evt;
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    evt->bytes        = 0;
    evt->op           = FILE_OP_RENAME;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (resolve_dirfd_path(evt->path, sizeof(evt->path), tgid, old_dirfd, old_path) != 0 || is_noise_path(evt->path) ||
        path_is_systemd_private_tmp_noise(evt->path)) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    // The source path is the primary relevance gate for rename events. Keep the
    // destination path as auxiliary context, but avoid resolving it against
    // new_dirfd here because doing two full dirfd resolutions pushes this
    // tracepoint over the verifier instruction budget on real kernels. As a
    // result, evt->new_path may remain relative for renameat2 calls that pass a
    // relative destination path, and userspace policy matching should not treat
    // it as guaranteed-absolute.
    if (new_path && copy_user_path(evt->new_path, sizeof(evt->new_path), new_path) != 0) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __noinline int submit_hardlink_paths(const char *old_path, long old_dirfd, const char *new_path) {
    struct event *evt;
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    evt->bytes        = 0;
    evt->op           = FILE_OP_HARDLINK;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (resolve_dirfd_path(evt->path, sizeof(evt->path), tgid, old_dirfd, old_path) != 0 || is_noise_path(evt->path) ||
        path_is_systemd_private_tmp_noise(evt->path)) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    // As with rename, keep the source path as the primary relevance gate and
    // avoid a second dirfd resolution for the destination. Doing two full
    // resolutions here risks blowing the verifier budget on real kernels. As a
    // result, evt->new_path may remain relative for link/linkat calls that pass
    // a relative destination path, and userspace should not treat it as
    // guaranteed-absolute.
    if (new_path && copy_user_path(evt->new_path, sizeof(evt->new_path), new_path) != 0) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __noinline int submit_symlink_paths(const char *old_path, const char *new_path, long new_dirfd) {
    struct event *evt;
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    evt->bytes        = 0;
    evt->op           = FILE_OP_SYMLINK;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (copy_user_path(evt->path, sizeof(evt->path), old_path) != 0) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    // The symlink target string is stored verbatim in the inode. Keep
    // evt->path as-is because a relative target is intentionally relative to
    // the link itself. Resolve the link pathname (evt->new_path) when we can,
    // but it may still remain relative for AT_FDCWD-based calls or untracked
    // dirfds because this probe does not track task cwd.
    if (resolve_dirfd_path(evt->new_path, sizeof(evt->new_path), tgid, new_dirfd, new_path) != 0 ||
        is_noise_path(evt->new_path) || path_is_systemd_private_tmp_noise(evt->new_path)) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __always_inline int remember_open_path(const char *filename, long dirfd, u64 flags) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct path_value *path;
    u32 zero = 0;
    u32 tgid = (u32)(pid_tgid >> 32);

    path = bpf_map_lookup_elem(&path_heap, &zero);
    if (!path) {
        return 0;
    }
    __builtin_memset(path, 0, sizeof(*path));

    if (resolve_dirfd_path(path->path, sizeof(path->path), tgid, dirfd, filename) != 0) {
        return 0;
    }
    if (is_noise_path(path->path)) {
        return 0;
    }
    path->open_flags = flags;

    bpf_map_update_elem(&inflight_open, &pid_tgid, path, BPF_ANY);
    return 0;
}

static __always_inline u64 read_openat2_flags(const struct enter_openat2_ctx *ctx) {
    struct open_how how = {};

    if (!ctx->how) {
        return 0;
    }
    if (bpf_probe_read_user(&how, sizeof(how), ctx->how) != 0) {
        return 0;
    }
    return how.flags;
}

static __always_inline int finalize_open_fd(struct exit_ctx *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct path_value *path;
    struct fd_key key = {};

    path = bpf_map_lookup_elem(&inflight_open, &pid_tgid);
    if (!path) {
        return 0;
    }

    if (ctx->ret >= 0) {
        key.tgid = pid_tgid >> 32;
        key.fd   = (u32)ctx->ret;
        bpf_map_update_elem(&fd_paths, &key, path, BPF_ANY);
        submit_open_event(path);
    }

    bpf_map_delete_elem(&inflight_open, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct enter_open_ctx *ctx) {
    return remember_open_path(ctx->filename, AT_FDCWD, (u64)ctx->flags);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct enter_openat_ctx *ctx) {
    return remember_open_path(ctx->filename, ctx->dfd, (u64)ctx->flags);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_enter_openat2(struct enter_openat2_ctx *ctx) {
    return remember_open_path(ctx->filename, ctx->dfd, read_openat2_flags(ctx));
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_exit_open(struct exit_ctx *ctx) {
    return finalize_open_fd(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct exit_ctx *ctx) {
    return finalize_open_fd(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_exit_openat2(struct exit_ctx *ctx) {
    return finalize_open_fd(ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct enter_rw_ctx *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 fd       = (u32)ctx->fd;

    if (ctx->count == 0) {
        return 0;
    }
    bpf_map_update_elem(&inflight_write, &pid_tgid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct exit_ctx *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 *fd;
    struct fd_key key = {.tgid = (u32)(pid_tgid >> 32)};
    struct path_value *path;

    fd = bpf_map_lookup_elem(&inflight_write, &pid_tgid);
    if (!fd) {
        return 0;
    }
    if (ctx->ret > 0) {
        key.fd = *fd;
        path   = bpf_map_lookup_elem(&fd_paths, &key);
        if (path) {
            path->write_bytes += (u64)ctx->ret;
            set_seen_flag(path, FD_SEEN_WRITE);
        }
    }
    bpf_map_delete_elem(&inflight_write, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct enter_mmap_ctx *ctx) {
    struct fd_key key = {.tgid = (u32)(bpf_get_current_pid_tgid() >> 32), .fd = (u32)ctx->fd};
    struct path_value *path;

    if ((long)ctx->fd < 0) {
        return 0;
    }
    path = bpf_map_lookup_elem(&fd_paths, &key);
    if (!path) {
        return 0;
    }

    if ((ctx->prot & PROT_WRITE) == 0 && !has_seen_flag(path, FD_SEEN_MMAP_READ)) {
        set_seen_flag(path, FD_SEEN_MMAP_READ);
        submit_fd_event(path, FILE_OP_MMAP_READ, 0);
    }
    if ((ctx->prot & PROT_WRITE) && !has_seen_flag(path, FD_SEEN_MMAP_WRITE)) {
        set_seen_flag(path, FD_SEEN_MMAP_WRITE);
        submit_fd_event(path, FILE_OP_MMAP_WRITE, 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct enter_close_ctx *ctx) {
    struct fd_key key = {.tgid = (u32)(bpf_get_current_pid_tgid() >> 32), .fd = ctx->fd};
    struct path_value *path;

    path = bpf_map_lookup_elem(&fd_paths, &key);
    if (!path) {
        return 0;
    }

    if (has_seen_flag(path, FD_SEEN_WRITE)) {
        submit_fd_event(path, FILE_OP_WRITE, path->write_bytes);
    }

    bpf_map_delete_elem(&fd_paths, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_delete(struct enter_unlinkat_ctx *ctx) {
    return submit_delete_path(ctx->pathname, ctx->dfd);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct enter_rename_ctx *ctx) {
    return submit_rename_paths(ctx->oldname, AT_FDCWD, ctx->newname);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct enter_renameat_ctx *ctx) {
    return submit_rename_paths(ctx->oldname, ctx->olddfd, ctx->newname);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct enter_renameat2_ctx *ctx) {
    return submit_rename_paths(ctx->oldname, ctx->olddfd, ctx->newname);
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_link(struct enter_link_ctx *ctx) {
    return submit_hardlink_paths(ctx->oldname, AT_FDCWD, ctx->newname);
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_linkat(struct enter_linkat_ctx *ctx) {
    return submit_hardlink_paths(ctx->oldname, ctx->olddfd, ctx->newname);
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_symlink(struct enter_symlink_ctx *ctx) {
    return submit_symlink_paths(ctx->oldname, ctx->newname, AT_FDCWD);
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_symlinkat(struct enter_symlinkat_ctx *ctx) {
    return submit_symlink_paths(ctx->oldname, ctx->newname, ctx->newdfd);
}
