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

// #include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define SYM_H_NO_DEF // don't include definition of sym.h, because it is included in record.c
#include "sym.h"
#include "stack.h"
#include "record.skel.h"
#include "record.h"

/* kernel symbol table */
struct ksyms* ksym_tb;
/* user symbol table */
struct usyms* usym_tb;

struct stack_ag* stack_aggre(struct bpf_map *stack_map, struct bpf_map *sample, int *pids, int num_of_pids)
{

	struct stack_ag* stack_ag_p = NULL;

	int stack_map_fd = bpf_map__fd(stack_map);
	int sample_fd = bpf_map__fd(sample);

	struct key_t a = {}, b = {};
	struct key_t *last_key = &a;
	struct key_t *cur_key = &b;

	unsigned long long *frame = calloc(PERF_MAX_STACK_DEPTH, sizeof(unsigned long long));
	int err;
	int sample_num = 0;

	/* symbol table */
	ksym_tb = ksym_load();
	usym_tb = usym_load(pids, num_of_pids);
	if (ksym_tb == NULL || usym_tb == NULL) {
		printf("Failed to load symbols when aggregating stack\n");
		return NULL;
	}

	while (bpf_map_get_next_key(sample_fd, last_key, cur_key) == 0) {

		if (stack_ag_p == NULL) {
			/* initialize root stack aggregation pointer */
			stack_ag_p = malloc(sizeof(struct stack_ag));
			stack_ag_p->next = NULL;
			stack_ag_p->child = NULL;
			strcpy(stack_ag_p->name, "all");
			stack_ag_p->cnt = 0;
		}

		bpf_map_lookup_elem(sample_fd, &cur_key, &sample_num);

		/* stack frame */
		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->kern_stack_id, frame);
		/* kernel stack not available */
		if (cur_key->kern_stack_id != -EFAULT) {
			if (err)
				printf("\n[kernel stack lost]\n");
			else
				stack_insert(stack_ag_p, frame, PERF_MAX_STACK_DEPTH, 'k');
		}

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->user_stack_id, frame);
		if (err)
			printf("\n[user stack lost]\n");
		else
			stack_insert(stack_ag_p, frame, PERF_MAX_STACK_DEPTH, 'u');

		last_key = cur_key;

	} 

	return stack_ag_p;
}

int stack_insert(struct stack_ag* stack_ag_p, unsigned long long* frame, int frame_sz, char mode)
{
	struct stack_ag *p = stack_ag_p;
	char name[128];
	int index = 0;
	struct stack_ag *p_parent = NULL;

	int err = 0;

	/* cnt+1 the existed prefix */
	while (p && index < frame_sz && frame[index]) {
		if (mode == 'k') {
			err = ksym_addr_to_sym(ksym_tb, frame[index++], name);
		} else if (mode == 'u') {
			err = usym_addr_to_sym(usym_tb, frame[index++], name);
		}
		if (err)
			goto return_err;
		if (strcmp(p->name, name) == 0) {
			++p->cnt;
			if (p->child == NULL) {
				p_parent = p;
				break;
			}
			p = p->child;
		} else if (p->next) {
			p = p->next;
		} else {
			struct stack_ag *tmp = malloc(sizeof(struct stack_ag));
			if (tmp == NULL) {
				err = -1;
				goto return_err;
			}

			tmp->next = NULL;
			tmp->child = NULL;
			strcpy(tmp->name, name);
			tmp->cnt = 0;
			p->next = tmp;

			p_parent = tmp;
			break;
		}
	}

	/* add the rest of the children */
	// TODO: should I judge if p_parent is NULL?
	for (;frame[index] && index < frame_sz;index++){

		if (mode == 'k') {
			err = ksym_addr_to_sym(ksym_tb, frame[index++], name);
		} else if (mode == 'u') {
			err = usym_addr_to_sym(usym_tb, frame[index++], name);
		}
		if (err)
			goto return_err;

		struct stack_ag *tmp = malloc(sizeof(struct stack_ag));
		if (tmp == NULL) {
			err = -1;
			goto return_err;
		}

		tmp->next = NULL;
		tmp->child = NULL;
		strcpy(tmp->name, name);
		tmp->cnt = 0;

		p_parent->child = tmp;
		p_parent = tmp;
	}

return_err:
	return err;
}

void stack_free(struct stack_ag* p) {
	if (p == NULL)
		return;

	stack_free(p->next);
	stack_free(p->child);
	free(p);
}
