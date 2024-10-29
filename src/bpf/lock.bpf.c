/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#include "vmlinux.h"
#include "event.h"
#include "bpf_util.h"
#include "util.h"

#define MAX_ENTRIES 204800
#define MAX_STACKS 32
#define MAX_ 10
#define MAX_HW 10
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile bool enabled;
volatile bool spec_pid;
volatile bool collect_stack;

struct lock_key {
	int pid;
	int tgid;
	int stack_id;
};

struct internal_data {
	int stack_id;
	__u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int); // pid
	__type(value, struct internal_data);
	__uint(max_entries, MAX_ENTRIES);
} internal SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lock_key);
	__type(value, __u64);
	__uint(max_entries, MAX_ENTRIES);
} wait_time SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(value_size, MAX_STACKS * sizeof(u64));
	__type(key, u32);
	__uint(max_entries, MAX_ENTRIES);
} stack_map SEC(".maps");

SEC("uprobe")
int exit_wait(void *ctx)
{
	if (!enabled)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	__u64 *last, tgid_pid = bpf_get_current_pid_tgid(), zero = 0;
	int tgid = tgid_pid >> 32, pid = tgid_pid;
	struct internal_data *d;

	if (spec_pid && filter_pid(tgid))
		return 0;

	d = bpf_map_lookup_elem(&internal, &pid);
	if (d) {
		struct lock_key k = {
			.pid = pid,
			.tgid = tgid,
			.stack_id = d->stack_id,
		};
		ts = ts - d->ts;
		// TODO: what if the same pid & stack_id tuple appears
		// twice
		bpf_map_update_elem(&wait_time, &k, &ts, BPF_ANY); 
	}

	return 0;
}

SEC("uprobe")
int enter_wait(void *ctx)
{
	if (!enabled)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	__u64 *last, tgid_pid = bpf_get_current_pid_tgid(), zero = 0;
	int stack_id, tgid = tgid_pid >> 32, pid = tgid_pid;

	if (spec_pid && filter_pid(tgid))
		return 0;
		
	stack_id = bpf_get_stackid(ctx, &stack_map, 
				       BPF_F_USER_STACK | \
				       BPF_F_FAST_STACK_CMP);

	struct internal_data d = {
		.stack_id = stack_id,
		.ts = ts,
	};


	bpf_map_update_elem(&internal, &pid, &d, BPF_ANY);

	return 0;
}
