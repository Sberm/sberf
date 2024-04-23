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

#include "vmlinux.h"
#include "event.h"
#include "bpf_util.h"
#include "util.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile bool enable;

struct common_fields {
	unsigned short common_type;	
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
};

struct tp_args {
	struct common_fields cf;
	long syscall_nr;
	u64 args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u8));
	__uint(max_entries, 1);
} task_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, 512);
} event_filter SEC(".maps");

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
	__type(value, u32);
	__uint(max_entries, MAX_ENTRIES);
} event_cnt SEC(".maps");

static int inline filter_pid(pid_t pid)
{
	if (!bpf_map_lookup_elem(&task_filter, &pid))
		return 1;
	else
		return 0;
}

// TODO: is it necessary
static int inline filter_syscall_nr(long syscall_nr)
{
	if (!bpf_map_lookup_elem(&event_filter, &syscall_nr))
		return 1;
	else
		return 0;
}

TP_TRGR(0)
TP_TRGR(1)
TP_TRGR(2)
TP_TRGR(3)
TP_TRGR(4)
TP_TRGR(5)

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
