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

/*struct {*/
	/*__uint(type, BPF_MAP_TYPE_RINGBUF);*/
	/*__uint(max_entries, 256 * 1024);*/
/*} events SEC(".maps");*/

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
	bpf_printk("ok this is tracing");

	int pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != pid_to_trace)
		return 0;

	bpf_printk("ok this is tracing");

	/*int pid = bpf_get_current_pid_tgid() >> 32;*/
	int cpu_id = bpf_get_smp_processor_id();
	struct event *e = NULL;
	int cp;

	/*event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);*/
	if (bpf_map_update_elem(&events, &pid, &empty_event, BPF_ANY)) {
		bpf_printk("Failed to create event");
		return 0;
	}

	e = bpf_map_lookup_elem(&events, &pid_to_trace);

	if (!e)
		return 1;

	e->pid = pid_to_trace;
	e->cpu_id = cpu_id;

	if (bpf_get_current_comm(e->comm, sizeof(e->comm)))
		e->comm[0] = 0;

	e->kstack_sz = bpf_get_stack(ctx, e->kstack, sizeof(e->kstack), 0);

	e->ustack_sz =
		bpf_get_stack(ctx, e->ustack, sizeof(e->ustack), BPF_F_USER_STACK);

	/*bpf_ringbuf_submit(e, 0);*/
	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}

// #include "vmlinux.h"
// 
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>
// 
// #include "record.h"
// 
// char LICENSE[] SEC("license") = "Dual BSD/GPL";
// 
// pid_t pid_to_trace;
// 
// static const struct event empty_event = {};
// 
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 8192);
// 	__type(key, pid_t);
// 	__type(value, struct event); // u64定义在vmlinux.h中
// } exec_start SEC(".maps");
// 
// struct {
// 	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
// 	__uint(key_size, sizeof(u32));
// 	__uint(value_size, sizeof(u32));
// } pb SEC(".maps");
// 
// const volatile unsigned long long min_duration_ns = -1;
// 
// SEC("tp/sched/sched_process_exec")
// int handle_exec(struct trace_event_raw_sys_enter *ctx)
// {
// 	struct task_struct *task;
// 	unsigned fname_off;
// 	struct event *e;
// 	pid_t pid;
// 	u64 ts;
// 
// 	/* remember time exec() was executed for this PID */
// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	ts = bpf_ktime_get_ns();
// 
// 	bpf_printk("[EXEC] %d", pid);
// 
// 	if (bpf_map_update_elem(&exec_start, &pid, &empty_event, BPF_NOEXIST)) {
// 		return 0;
// 	}
// 
// 	e = bpf_map_lookup_elem(&exec_start, &pid);
// 	if (!e) {
// 		return 0;
// 	}
// 
// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();
// 
// 	e->exit_event = 0;
// 	e->pid = pid;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	e->ts = ts;
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));
// 
// 	bpf_printk("ppid %d ts %llu comm %s", e->ppid, e->ts, e->comm);
// 
// 	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
// 
// 	return 0;
// }
// 
// SEC("tp/sched/sched_process_exit")
// int handle_exit(struct trace_event_raw_sys_exit *ctx)
// {
// 	struct task_struct *task;
// 	struct event *e;
// 	pid_t pid, tid;
// 	u64 id, ts, *start_ts, duration_ns = 0;
// 
// 	/* get PID and TID of exiting thread/process */
// 	id = bpf_get_current_pid_tgid();
// 	pid = id >> 32;
// 	tid = (u32)id;
// 
// 	/* ignore thread exits */
// 	if (pid != tid)
// 		return 0;
// 
// 	bpf_printk("[EXIT] %d",pid);
// 
// 	/* if we recorded start of the process, calculate lifetime duration */
// 	e = bpf_map_lookup_elem(&exec_start, &pid);
// 
// 	if (e)
// 		duration_ns = bpf_ktime_get_ns() - e->ts;
// 	else if (min_duration_ns)
// 		return 0;
// 	else
// 		return 0;
// 
// 	/* if process didn't live long enough, return early */
// 	if (min_duration_ns && duration_ns < min_duration_ns)
// 		return 0;
// 
// 	/* fill out the sample with data */
// 	task = (struct task_struct *)bpf_get_current_task();
// 
// 	e->exit_event = 1;
// 	e->duration_ns = duration_ns;
// 	e->pid = pid;
// 	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
// 	bpf_get_current_comm(&e->comm, sizeof(e->comm));
// 
// 	bpf_printk("ON EXIT: exit_event %d duration %llu comm %s", e->exit_event, e->duration_ns, e->comm);
// 
// 	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
// 
// cleanup:
// 
// 	bpf_map_delete_elem(&exec_start, &pid);
// 	return 0;
// }
// 
