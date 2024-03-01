/*-*- coding:utf-8                                                          -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2023 Howard Chu                                                    │
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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "record.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

pid_t pid_to_trace;

static const struct event empty_event = {};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, struct event); // u64定义在vmlinux.h中
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} pb SEC(".maps");

SEC("perf_event")
int profile(struct bpf_perf_event_data *ctx)
{
	// TODO: has to be the same pid?
	int pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != pid_to_trace)
		return 0;

	int cpu_id = bpf_get_smp_processor_id();
	struct event *e = NULL;
	int cp;

	if (bpf_map_update_elem(&events, &pid, &empty_event, BPF_ANY)) {
		bpf_printk("Failed to update create event");
		return 0;
	}

	e = bpf_map_lookup_elem(&events, &pid_to_trace);

	if (!e) {
		bpf_printk("Failed to retrieve event");
		return 0;
	}

	e->pid = pid_to_trace;
	e->cpu_id = cpu_id;

	if (bpf_get_current_comm(e->comm, sizeof(e->comm)))
		e->comm[0] = 0;

	e->kstack_sz = bpf_get_stack(ctx, e->kstack, sizeof(e->kstack), 0);
	e->ustack_sz = bpf_get_stack(ctx, e->ustack, sizeof(e->ustack), BPF_F_USER_STACK);

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}
