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
#include "off_cpu.h"
#include "bpf_util.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct sched_switch_args {
	unsigned long long common_fields;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	pid_t next_pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, __u32);
	__type(value, MAX_STACKS * sizeof(__u64));
	__uint(max_entries, MAX_ENTRIES);
} stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct off_cpu_key);
	__type(value, struct off_cpu_data);
	__uint(max_entries, MAX_ENTRIES);
} off_cpu SEC(".maps");

SEC("tp/sched/sched_switch")
int sched_switch(void* ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u32 stack_id;
	__u64 zero = 0;
	struct task_struct *prev, *next; 

	bpf_core_read(&prev, sizeof(void *), &ctx[1]);
	bpf_core_read(&next, sizeof(void *), &ctx[2]);

	stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);

	struct off_cpu_key key_p = {
		.pid = prev->pid,
		.tgid = prev->tgid,	
	};

	struct off_cpu_data *od = bpf_map_lookup_elem(&off_cpu, &key_p);

	if (od) {	
		od->ts = ts;
		od->stack_id = stack_id;
	}

	// next	
	
	struct off_cpu_key key_n = {
		.pid = next->pid,
		.tgid = next->tgid,
	};

	od = bpf_map_lookup_elem(&off_cpu, &key_n);

	if (od) {
		od->total += ts - od->ts;
		od->ts = 0;
	}
	
	return 0;
}

SEC("tp/task/task_newtask")
int new_task(void* ctx)
{
	u64 ts = bpf_ktime_get_ns();

	struct task_struct *task = (struct task_struct*)bpf_get_current_task();

	struct off_cpu_key key = {
		.pid = task->pid,
		.tgid = task->tgid,
	};

	struct off_cpu_data od = {
		.ts = 0,
		.total = 0,
		.stack_id = 0,
	};

	bpf_map_update_elem(&off_cpu, &key, &od, BPF_NOEXIST);

	return 0;
}
