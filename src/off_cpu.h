/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef OFF_CPU_H
#define OFF_CPU_H

#define MAX_ENTRIES 204800
#define MAX_STACKS 32
#define TASK_COMM_LEN 16

// user-space fetching
struct off_cpu_key {
	int pid;
	int tgid;
	int stack_id;
	char comm[TASK_COMM_LEN];
};

// BPF-side handling
struct internal_data {
	int stack_id;
	unsigned long long ts;
};

struct internal_key {
	int pid;
	int tgid;
};

#endif 
