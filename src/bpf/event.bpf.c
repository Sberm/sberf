/*-*- coding:utf-8                                                          -*-│
│vi: set ft=c ts=8 sts=8 sw=8 fenc=utf-8                                    :vi│
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

#include "vmlinux.h"
#include "event.h"
#include "bpf_util.h"
#include "util.h"

#define MAX_ENTRIES 204800
#define MAX_STACKS 32
#define MAX_EVENTS 10
#define MAX_HW 10
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile bool enabled;
volatile bool spec_pid;
volatile bool collect_stack;

struct key_t {
	__u32 pid;
	int ustack_id;
	int kstack_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, MAX_EVENTS);
} event_cnt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(value_size, MAX_STACKS * sizeof(u64));
	__type(key, u32);
	__uint(max_entries, MAX_ENTRIES);
} stack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, __u64);
    __uint(max_entries, MAX_ENTRIES);
} sample SEC(".maps");

TP_TRGR(0)
TP_TRGR(1)
TP_TRGR(2)
TP_TRGR(3)
TP_TRGR(4)
TP_TRGR(5)
TP_TRGR(6)
TP_TRGR(7)
TP_TRGR(8)
TP_TRGR(9)

SEC("kprobe")
int kprobe_trgr(void *ctx)
{
	if (!enabled)
		return 0;

	__u64 *cnt, tgid_pid = bpf_get_current_pid_tgid();
	__u64 zero = 0;
	pid_t tgid = tgid_pid >> 32;
	__u32 key = 0;

	if (spec_pid && filter_pid(tgid))
		return 0;

	cnt = bpf_map_lookup_insert(&event_cnt, &key, &zero);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else
		return -1;

	if (collect_stack) {
		struct key_t key;
		key.pid = tgid;
		key.kstack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_FAST_STACK_CMP);
		key.ustack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);

		u64 *key_samp;
		key_samp = bpf_map_lookup_insert(&sample, &key, &zero);

		if (key_samp)
			__sync_fetch_and_add(key_samp, 1);
		else {
			bpf_printk("Failed to look up stack sample");
			return -1;
		}
	}

	return 0;
}

SEC("uprobe")
int uprobe_trgr(void *ctx)
{
	if (!enabled)
		return 0;

	__u64 *cnt, tgid_pid = bpf_get_current_pid_tgid();
	__u64 zero = 0;
	pid_t tgid = tgid_pid >> 32;
	__u32 key = 0;

	if (spec_pid && filter_pid(tgid))
		return 0;

	cnt = bpf_map_lookup_insert(&event_cnt, &key, &zero);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else
		return -1;

	if (collect_stack) {
		struct key_t key;
		key.pid = tgid;
		key.kstack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_FAST_STACK_CMP);
		key.ustack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);

		u64 *key_samp;
		key_samp = bpf_map_lookup_insert(&sample, &key, &zero);

		if (key_samp)
			__sync_fetch_and_add(key_samp, 1);
		else {
			bpf_printk("Failed to look up stack sample");
			return -1;
		}
	}

	return 0;
}
