/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef STACK_H
#define STACK_H

#include <bpf/libbpf.h>
#include <stdbool.h>
#include "comm.h"

struct stack_ag {
	struct stack_ag *next;
	struct stack_ag *child;
	unsigned long long cnt;
	bool is_comm;
	pid_t pid;
	union {
		char comm[16];
		unsigned long long addr;
	};
};

int stack_walk(struct stack_ag* p);
struct stack_ag* stack_aggre_off_cpu(struct bpf_map *stack_map, struct bpf_map *sample, struct comm_pids *comms);
struct stack_ag* stack_aggre(struct bpf_map *stack_map, struct bpf_map *sample, struct comm_pids *comms);
int stack_insert(struct stack_ag* stack_ag_p, unsigned long long* frame, unsigned long long sample_num, int frame_sz);
void stack_free(struct stack_ag* stack_ag_p);
int stack_get_least_sample(struct stack_ag* p);
struct stack_ag *comm_lookup_insert(struct stack_ag *stack_ag_p, char* comm);
int stack_get_depth(struct stack_ag* p);

#endif
