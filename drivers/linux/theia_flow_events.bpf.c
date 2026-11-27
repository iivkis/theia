/* SPDX-License-Identifier: GPL-2.0-only
 * Theia isolated attribution collector. No route changes and no automatic
 * attach. A trusted loader must own the cgroup links and private ringbuf.
 * Missing/dropped events cannot authorize native routing.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct flow_event {
    __u64 cookie;
    __u64 timestamp;
    __u64 process_start;
    __u64 inode;
    __u64 pid_tgid;
    __u32 dev_major;
    __u32 dev_minor;
    __u32 family;
    __u32 protocol;
    __u32 kind;
    __u32 reserved;
    __u8 remote_ip[16];
    __u16 remote_port;
    __u8 reserved2[6];
};
_Static_assert(sizeof(struct flow_event) == 88, "wire layout");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} flow_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost_events SEC(".maps");

static __always_inline void lost(void) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&lost_events, &key);
    if (count) (*count)++;
}

static __always_inline int observe(struct bpf_sock_addr *ctx, __u32 family, __u32 kind) {
    struct flow_event event = {};
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task || (ctx->protocol != 6 && ctx->protocol != 17) ||
        (kind == 2 && ctx->protocol != 17)) return 1;
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    struct file *exe = mm ? BPF_CORE_READ(mm, exe_file) : 0;
    struct inode *inode = exe ? BPF_CORE_READ(exe, f_inode) : 0;
    struct super_block *sb = inode ? BPF_CORE_READ(inode, i_sb) : 0;
    if (!leader || !inode || !sb) { lost(); return 1; }
    __u32 dev = BPF_CORE_READ(sb, s_dev);
    event.cookie = bpf_get_socket_cookie(ctx);
    event.timestamp = bpf_ktime_get_ns();
    event.process_start = BPF_CORE_READ(leader, start_boottime);
    event.inode = BPF_CORE_READ(inode, i_ino);
    event.pid_tgid = bpf_get_current_pid_tgid();
    event.dev_major = dev >> 20;
    event.dev_minor = dev & ((1U << 20) - 1);
    event.family = family;
    event.protocol = ctx->protocol;
    event.kind = kind;
    event.remote_port = bpf_ntohs((__u16)ctx->user_port);
    if (family == 4) __builtin_memcpy(event.remote_ip, &ctx->user_ip4, 4);
    else __builtin_memcpy(event.remote_ip, ctx->user_ip6, 16);
    if (!event.cookie || !event.process_start || !event.inode || !event.remote_port) {
        lost();
        return 1;
    }
    if (bpf_ringbuf_output(&flow_events, &event, sizeof(event), 0)) lost();
    return 1; /* observations only */
}

SEC("cgroup/connect4")
int theia_connect4(struct bpf_sock_addr *ctx) { return observe(ctx, 4, 1); }
SEC("cgroup/connect6")
int theia_connect6(struct bpf_sock_addr *ctx) { return observe(ctx, 6, 1); }
SEC("cgroup/sendmsg4")
int theia_sendmsg4(struct bpf_sock_addr *ctx) { return observe(ctx, 4, 2); }
SEC("cgroup/sendmsg6")
int theia_sendmsg6(struct bpf_sock_addr *ctx) { return observe(ctx, 6, 2); }

char LICENSE[] SEC("license") = "GPL";
