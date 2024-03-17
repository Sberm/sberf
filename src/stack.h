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

#ifndef STACK_H
#define STACK_H

#include <bpf/libbpf.h>

struct stack_ag {
	struct stack_ag *next;
	struct stack_ag *child;
	unsigned long long addr;
	unsigned int cnt;
	char comm[16];
};

int stack_walk(struct stack_ag* p);
struct stack_ag *stack_aggre(struct bpf_map *stack_map, struct bpf_map *sample);
int stack_insert(struct stack_ag* stack_ag_p, unsigned long long* frame, int sample_num, int frame_sz);
void stack_free(struct stack_ag* stack_ag_p);
int stack_get_least_sample(struct stack_ag* p);
struct stack_ag *comm_lookup_insert(struct stack_ag *stack_ag_p, char* comm);

#endif
