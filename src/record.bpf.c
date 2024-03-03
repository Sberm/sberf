/*-*- coding:utf-8                                                          -*-│
│vi: set net ft=c ts=4 sts=4 sw=4 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2024 Howard Chu                                                    │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/

/*
 * Based on profile from BCC by Brendan Gregg and others.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "record.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// specific pid
volatile bool spec_pid = false;
volatile pid_t pid_to_trace[MAX_PID] = {0};

// init value for insertion into map
static const u64 zero;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, key_t);
    __type(value, u64);
} sample SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key, u32);
} stack_map SEC(".maps");


SEC("perf_event")
int profile(struct bpf_perf_event_data *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	// if to trace only specific pids
	if (spec_pid) {
		for (int i = 0;i < ARRAY_LEN(pid_to_trace); i++) {
			if (pid_to_trace[i] == 0)
				return 0;
			if (pid_to_trace[i] == pid)
				break;
		}
		return 0;
	}
	
	struct key_t key = {}

	key_samp = bpf_map_lookup_insert(&key, &stack_map, &zero);
	if (key_samp)
		__sync_fetch_and_add(valp, 1);
	else {
		bpf_printk("Failed to look up stack sample");
		return -1;
	}

	key.pid = pid;
	key.user_stack_id = bpf_get_stackid(&ctx->regs, &stack_map, BPF_F_USER_STACK)
	key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stack_map, 0)
	bpf_get_current_comm(&key.comm, sizeof(key.comm));

	return 0;
}
