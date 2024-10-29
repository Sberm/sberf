/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#include "vmlinux.h"
#include "mem.h"
#include "bpf_util.h"
#include "util.h"

#define MAX_RAW_SYSCALL_ARGS 6
#define MAX_ENTRIES 204800
#define MAX_STACKS 32

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile bool enabled;
volatile bool spec_pid;

struct arg {
	int syscall_nr;
	unsigned long args[MAX_RAW_SYSCALL_ARGS];
};

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(value_size, MAX_STACKS * sizeof(u64));
	__type(key, u32);
	__uint(max_entries, MAX_ENTRIES);
} stack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_ENTRIES);
} mem_usage SEC(".maps");

volatile bool spec_pid;

SEC("tp/syscalls/sys_enter_mmap")
int mem_profile(struct arg* args)
{
	if (!enabled)
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	if (filter_pid(pid))
		return 0;
	
	return 0;
}
