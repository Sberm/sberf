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

#ifndef STACK_H
#define STACK_H

#include <bpf/libbpf.h>
#include <stdbool.h>

struct stack_ag {
	struct stack_ag *next;
	struct stack_ag *child;
	unsigned long long cnt;
	bool is_comm;
	union {
		char comm[16];
		unsigned long long addr;
	};
};

int stack_walk(struct stack_ag* p);
struct stack_ag* stack_aggre_off_cpu(struct bpf_map *stack_map, struct bpf_map *sample, int *pids, int *pid_nr);
struct stack_ag* stack_aggre(struct bpf_map *stack_map, struct bpf_map *sample, int *pids, int *pid_nr);
int stack_insert(struct stack_ag* stack_ag_p, unsigned long long* frame, unsigned long long sample_num, int frame_sz);
void stack_free(struct stack_ag* stack_ag_p);
int stack_get_least_sample(struct stack_ag* p);
struct stack_ag *comm_lookup_insert(struct stack_ag *stack_ag_p, char* comm);
int stack_get_depth(struct stack_ag* p);

#endif
