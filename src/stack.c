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
#include "stack.h"
#include "record.skel.h"
#include "record.h"
#include "util.h"

int stack_walk(struct stack_ag* p)
{
	if (p == NULL)
		return 0;

	return stack_walk(p->child) + stack_walk(p->next) + p->cnt;
}

struct stack_ag* stack_aggre(struct bpf_map *stack_map, struct bpf_map *sample)
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
	// ksym_tb = ksym_load();
	// usym_tb = usym_load(pids, num_of_pids);
	// if (ksym_tb == NULL || usym_tb == NULL) {
	// 	printf("Failed to load symbols when aggregating stack\n");
	// 	return NULL;
	// }

	while (bpf_map_get_next_key(sample_fd, last_key, cur_key) == 0) {

		if (stack_ag_p == NULL) {
			/* initialize root stack aggregation pointer */
			stack_ag_p = malloc(sizeof(struct stack_ag));
			stack_ag_p->next = NULL;
			stack_ag_p->child = NULL;
			// strcpy(stack_ag_p->name, "all");
			stack_ag_p->addr = 0;
			stack_ag_p->cnt = 0;
		}

		bpf_map_lookup_elem(sample_fd, cur_key, &sample_num);

		/* stack frame */
		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->kern_stack_id, frame);
		/* kernel stack not available */
		if (cur_key->kern_stack_id != -EFAULT) {
			if (err)
				printf("\n[kernel stack lost]\n");
			else {
				stack_insert(stack_ag_p, frame, sample_num, PERF_MAX_STACK_DEPTH);
			}
		}

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->user_stack_id, frame);
		if (err)
			printf("\n[user stack lost]\n");
		else
			stack_insert(stack_ag_p, frame, sample_num, PERF_MAX_STACK_DEPTH);

		last_key = cur_key;

	} 

	return stack_ag_p;
}

int stack_insert(struct stack_ag* stack_ag_p, unsigned long long* frame, int sample_num, int frame_sz)
{
	int err = 0;

	if (stack_ag_p == NULL) {
		printf("No stacks to aggregate\n");
		err = -1;
		goto return_err;
	}

	struct stack_ag *p = stack_ag_p;
	// char name[128];
	int index = 0;
	struct stack_ag *p_parent = NULL;

	/* add one for the root frame */
	p->cnt += sample_num;

	/* every stack frame is a child of root */
	p_parent = p;
	p = p->child;

	// move index to end
	for (;frame[index] && index < frame_sz;index++) {}
	--index;

	/* cnt+1 the existed prefix */
	while (p && index >= 0) {
		/*if (mode == 'k') {*/
			/*err = ksym_addr_to_sym(ksym_tb, frame[index], name);*/
		/*} else if (mode == 'u') {*/
			/*err = usym_addr_to_sym(usym_tb, frame[index], name);*/
		/*}*/
		/*if (err)*/
			/*goto return_err;*/

		// if (strcmp(p->name, name) == 0) {
		if (p->addr == frame[index]) {
			p->cnt += sample_num;
			--index;
			if (p->child == NULL) {
				p_parent = p;
				break;
			}
			p = p->child;
		} else if (p->next) {
			p = p->next;
		} else if (p->next == NULL){
			struct stack_ag *tmp = malloc(sizeof(struct stack_ag));
			if (tmp == NULL) {
				err = -1;
				goto return_err;
			}

			tmp->next = NULL;
			tmp->child = NULL;
			// strcpy(tmp->name, name);
			tmp->addr = frame[index];
			tmp->cnt = sample_num;
			p->next = tmp;
			--index;
			p_parent = tmp;
			break;
		} else {
			p_parent = p;
			break;
		}
	}

	/* add the rest of the children */
	for (;index >= 0;--index){
		/*if (mode == 'k') {*/
			/*err = ksym_addr_to_sym(ksym_tb, frame[index], name);*/
		/*} else if (mode == 'u') {*/
			/*err = usym_addr_to_sym(usym_tb, frame[index], name);*/
		/*}*/
		/*if (err)*/
			/*goto return_err;*/

		struct stack_ag *tmp = malloc(sizeof(struct stack_ag));
		if (tmp == NULL) {
			err = -1;
			goto return_err;
		}

		tmp->next = NULL;
		tmp->child = NULL;
		// strcpy(tmp->name, name);
		tmp->addr = frame[index];
		tmp->cnt = sample_num;

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

int stack_get_least_sample(struct stack_ag* p) {
	if (p == NULL)
		return 0;
	int a = stack_get_least_sample(p->child);
	int b = stack_get_least_sample(p->next);
	if (a == 0 && b == 0)
		return p->cnt;
	else if (a == 0)
		return min(p->cnt, b);
	else if (b == 0)
		return min(p->cnt, a);
	else
		return min(min(p->cnt, a), b);
}
