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

#define PF_KTHREAD   0x00200000
#define CLONE_THREAD  0x10000
#define TASK_INTERRUPTIBLE	0x0001
#define TASK_UNINTERRUPTIBLE	0x0002

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile bool enable;
volatile bool spec_pid;

struct task_struct__old {
    long state;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, int);
	__uint(value_size, MAX_STACKS * sizeof(__u64));
	__uint(max_entries, MAX_ENTRIES);
} stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct off_cpu_key);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} off_cpu_time SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct internal_key);
	__type(value, struct internal_data);
	__uint(max_entries, MAX_ENTRIES);
} internal_map SEC(".maps");

static inline int get_state(struct task_struct *ts)
{
	/*
	int state;
	if (bpf_core_field_exists(ts->__state)) {
		state = BPF_CORE_READ(ts, __state);
	} else {
		struct task_struct__old *ts_ = (void *)ts;
		state = BPF_CORE_READ(ts_, state);
	}
	*/

	return BPF_CORE_READ(ts, state);
}

static inline bool check_thread(struct task_struct *ts)
{
	if (ts->flags & PF_KTHREAD)
		return false;

	int state = get_state(ts);

	state &= 0xff;

	if (state != TASK_INTERRUPTIBLE && state != TASK_UNINTERRUPTIBLE)
		return false;

	return true;
}

SEC("tp_btf/sched_switch")
int sched_switch(u64 *ctx)
{

	if (!enable)
		return 0;

	u64 ts = bpf_ktime_get_ns();
	__u64 zero = 0;
	struct task_struct *prev, *next; 
	struct internal_data *id;
	pid_t tgid, pid;

	prev = (void *)ctx[1];
	next = (void *)ctx[2];

	tgid = BPF_CORE_READ(prev, tgid);
	pid = BPF_CORE_READ(prev, pid);

	struct internal_key key_p = {
		.tgid = tgid,
		.pid = pid,
	};

	struct internal_data tmp =  {
		.stack_id = -1,
		.ts = 0,
	};

	if (check_thread(prev)) {
		int stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
		id = bpf_map_lookup_insert(&internal_map, &key_p, &tmp);
		if (id) {
			if (stack_id >= 0)
				id->stack_id = stack_id;
			id->ts = ts;
		}
	}

	// next	
	tgid = BPF_CORE_READ(next, tgid);
	pid = BPF_CORE_READ(next, pid);

	if (spec_pid && filter_pid(tgid))
		return 0;

	struct internal_key key_n = {
		.tgid = tgid,
		.pid = pid,
	};

	id = bpf_map_lookup_elem(&internal_map, &key_n);

	if (id && id->ts) {
		struct off_cpu_key ok = {
			.pid = pid,
			.tgid = tgid,
			.stack_id = id->stack_id,
		};
		
		u64* total = bpf_map_lookup_insert(&off_cpu_time, &ok, &zero);
		if (total) {
			*total += ts - id->ts;
			id->ts = 0;
		}
	}

	return 0;
}
