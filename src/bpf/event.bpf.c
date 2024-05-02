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

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile bool enable;
volatile bool spec_pid;

struct stack_array {
	unsigned long array[MAX_STACKS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct stack_array);
	__uint(max_entries, 1);
} stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, __u32);
} pb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MAX_EVENTS);
} event_cnt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, MAX_HW);
} hw_cnt SEC(".maps");

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


SEC("perf_event")
int hardware(void *ctx)
{
	bpf_printk("h");

	if (!enable)
		return 0;

	__u64 *cnt, zero = 0;
	__u32 key = 0;

	cnt = bpf_map_lookup_insert(&hw_cnt, &key, &zero);
	if (cnt) {
		__sync_fetch_and_add(cnt, 1);
	} else {
		return -1;
	}

	return 0;
}

SEC("ksyscall")
int syscall_trgr(void *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid >> 32;

	if (filter_pid(pid))
		return 0;

	int zero = 0, len = 0;
	struct stack_array *sa = bpf_map_lookup_elem(&stacks, &zero);
	if (sa) {
		len = bpf_get_stack(ctx, sa->array, sizeof(sa->array), BPF_F_USER_STACK);
		if (len < 0)
			return 0;

		int output_len = sizeof(u64) * len;
		if (output_len <= sizeof(sa->array))
			bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, sa, output_len);
	}

	return 0;
}
