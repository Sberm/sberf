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
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "record.h"
#include "bpf_util.h"
#include "util.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// specific pid
volatile bool spec_pid = false;
volatile pid_t pids[MAX_PID] = {0};

// init value for insertion into map
static const u64 zero;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
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
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	// if to trace only specific pids
	if (spec_pid) {
		int i;
		for (i = 0;i < ARRAY_LEN(pids); i++) {
			if (pids[i] == 0)
				return 0;
			if (pids[i] == pid)
				break;
		}
		/* didn't match through the whole pids array */
		if (i == ARRAY_LEN(pids))
			return 0;
	}

	struct key_t key1 = {};
	// struct key_t key2 = {};

	key1.pid = pid;
	// key2.pid = pid;
	bpf_get_current_comm(&key1.comm, sizeof(key1.comm));
	// bpf_get_current_comm(&key2.comm, sizeof(key2.comm));

	key1.kern_stack_id = bpf_get_stackid(&ctx->regs, &stack_map, 0);
	// key2.kern_stack_id = bpf_get_stackid(&ctx->regs, &stack_map, 0);

	key1.user_stack_id = bpf_get_stackid(&ctx->regs, &stack_map, BPF_F_USER_STACK);
	// key2.user_stack_id = bpf_get_stackid(&ctx->regs, &stack_map, BPF_F_USER_STACK);

	u64* key_samp;
	key_samp = bpf_map_lookup_insert(&sample, &key1, &zero);
	if (key_samp)
		__sync_fetch_and_add(key_samp, 1);
	else {
		bpf_printk("Failed to look up stack sample");
		return -1;
	}

	/*key_samp = bpf_map_lookup_insert(&sample, &key2, &zero);*/
	/*if (key_samp)*/
		/*__sync_fetch_and_add(key_samp, 1);*/
	/*else {*/
		/*bpf_printk("Failed to look up stack sample");*/
		/*return -1;*/
	/*}*/

	return 0;
}
