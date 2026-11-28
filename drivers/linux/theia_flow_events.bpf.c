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

/* This hook sees the actual skb/socket, not a guessed tuple-to-PID
 * mapping. It runs on cgroup egress, not the earlier NFQUEUE LOCAL_OUT
 * hook: these records cannot be used to approve a queued packet.
 * No payload, mark changes, permits or process identity from softirq.
 */
struct packet_event {
    __u64 cookie;
    __u64 timestamp;
    __u32 family;
    __u32 protocol;
    __u32 ifindex;
    __u32 length;
    __u8 source[16];
    __u8 destination[16];
    __u16 source_port;
    __u16 destination_port;
    __u32 reserved;
};
_Static_assert(sizeof(struct packet_event) == 72, "packet wire layout");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} packet_events SEC(".maps");

/* 1 = BPF_HDR_START_NET. No IPv4 options, fragments, IPv6 extension
 * headers or offload assumptions in this first observation format.
 * An unsupported packet is intentionally not an attribution token.
 */
SEC("cgroup_skb/egress")
int theia_egress(struct __sk_buff *skb) {
    struct packet_event event = {};
    __u8 hdr[40] = {};
    __u8 ports[4] = {};
    __u32 offset;
    if (bpf_skb_load_bytes_relative(skb, 0, hdr, 20, 1)) return 1;
    if (hdr[0] == 0x45) {
        if ((hdr[6] & 0x3f) || hdr[7]) return 1;
        event.family = 4;
        event.protocol = hdr[9];
        __builtin_memcpy(event.source, hdr + 12, 4);
        __builtin_memcpy(event.destination, hdr + 16, 4);
        offset = 20;
    } else if ((hdr[0] >> 4) == 6) {
        if (bpf_skb_load_bytes_relative(skb, 0, hdr, 40, 1)) return 1;
        event.family = 6;
        event.protocol = hdr[6];
        __builtin_memcpy(event.source, hdr + 8, 16);
        __builtin_memcpy(event.destination, hdr + 24, 16);
        offset = 40;
    } else return 1;
    if (event.protocol != 6 && event.protocol != 17) return 1;
    if (skb->len < offset + (event.protocol == 6 ? 20 : 8) ||
        bpf_skb_load_bytes_relative(skb, offset, ports, 4, 1)) return 1;
    event.source_port = ((__u16)ports[0] << 8) | ports[1];
    event.destination_port = ((__u16)ports[2] << 8) | ports[3];
    if (!event.source_port || !event.destination_port) return 1;
    event.cookie = bpf_get_socket_cookie(skb);
    event.timestamp = bpf_ktime_get_ns();
    event.ifindex = skb->ifindex;
    event.length = skb->len;
    if (!event.cookie || !event.timestamp) { lost(); return 1; }
    if (bpf_ringbuf_output(&packet_events, &event, sizeof(event), 0)) lost();
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
