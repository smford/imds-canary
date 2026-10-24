//go:build ignore

#include "vmlinux.h"

volatile const __u16 redirect_port = 18080;

struct imds_event {
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	__u16 target_port;
	__u16 redir_port;
	__u32 orig_dst_ip;
	__u32 redir_dst_ip;
	char comm[16];
};

const struct imds_event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET)
		return 1;

	/*
	 * Destination IP check: 169.254.169.254
	 * In network byte order (little-endian word 0xFEA9FEA9).
	 * Destination Port check: 80 (htons(80)).
	 */
	if (ctx->user_ip4 != bpf_htonl(0xa9fea9fe) || ctx->user_port != bpf_htons(80))
		return 1;

	__u32 orig_ip = ctx->user_ip4;
	__u16 target_port = bpf_ntohs((__u16)ctx->user_port);
	__u16 r_port = redirect_port;

	/* Transparently rewrite destination to 127.0.0.1:<redirect_port> */
	ctx->user_ip4 = bpf_htonl(0x7f000001);
	ctx->user_port = bpf_htons(r_port);

	/* Emit telemetry event to ring buffer */
	struct imds_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 1;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	evt->tgid = pid_tgid >> 32; /* Process ID */
	evt->pid = (__u32)pid_tgid; /* Thread ID */
	evt->uid = (__u32)uid_gid;
	evt->gid = uid_gid >> 32;
	evt->target_port = target_port;
	evt->redir_port = r_port;
	evt->orig_dst_ip = orig_ip;
	evt->redir_dst_ip = ctx->user_ip4;
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));

	bpf_ringbuf_submit(evt, 0);

	return 1;
}

char _license[] SEC("license") = "Dual BSD/GPL";
