/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

/*
 * Based on profile from BCC by Brendan Gregg and others.
 */

#include "vmlinux.h"
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "record.h"
#include "bpf_util.h"
#include "util.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile bool enabled;
volatile bool spec_pid;

static const u64 zero;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
	__type(key, u32);
	__uint(max_entries, MAX_ENTRIES);
} stack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, u64);
    __uint(max_entries, MAX_ENTRIES);
} sample SEC(".maps");

SEC("perf_event")
int profile(struct bpf_perf_event_data *ctx)
{
	if (!enabled)
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u64 *val;

	if (spec_pid && filter_pid(pid))
		return 0;

	struct key_t key = {};

	key.pid = pid;
	key.kstack_id = bpf_get_stackid(&ctx->regs, &stack_map, 0);
	key.ustack_id = bpf_get_stackid(&ctx->regs, &stack_map, 
					BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);

	val = bpf_map_lookup_insert(&sample, &key, &zero);

	if (val)
		__sync_fetch_and_add(val, 1);
	else
		return -1;

	return 0;
}
