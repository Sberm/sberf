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

#include <bpf/bpf.h>
#include <stdbool.h>
#include <stdlib.h>
#include "stack.h"
#include "record.skel.h"
#include "record.h" // for key_t
#include "util.h"
#include "off_cpu.h"

#define DEBUG false
#define MAX_PID 128

bool find_pid(int *pids, int pid, int len)
{
	int l = 0, h = len - 1, m, pid_tmp;

	if (pids[h] < pid || pids[l] > pid)
		return false;

	while (l < h) {
		m = (l + h) / 2;
		pid_tmp = pids[m];
		if (pid_tmp == pid) {
			return true;
		} else if (pid_tmp < pid) {
			l = m + 1;
		} else if (pid_tmp > pid) {
			h = m - 1;
		}
	}
	return false;
}

int compar(const void *a, const void *b)
{
	return *(int *)a - *(int *)b;
}

int stack_walk(struct stack_ag* p)
{
	if (p == NULL)
		return 0;

	return stack_walk(p->child) + stack_walk(p->next) + p->cnt;
}

struct stack_ag* stack_aggre_off_cpu(struct bpf_map *stack_map, struct bpf_map *sample, int *pids, int *pid_nr)
{
	struct stack_ag *stack_ag_p = NULL;

	int stack_map_fd = bpf_map__fd(stack_map);
	int sample_fd = bpf_map__fd(sample);
	int err, pids_i = 0;

	struct off_cpu_key a = {}, b = {};
	struct off_cpu_key *last_key = &a;
	struct off_cpu_key *cur_key = &b;

	unsigned long long *frame = calloc(MAX_STACK_DEPTH, sizeof(unsigned long long));
	unsigned long long sample_time = 0;
	unsigned long long cnt = 0;

	while (bpf_map_get_next_key(sample_fd, last_key, cur_key) == 0) {
		if (stack_ag_p == NULL) {
			/* initialize root stack aggregation pointer */
			stack_ag_p = malloc(sizeof(struct stack_ag));
			stack_ag_p->next = NULL;
			stack_ag_p->child = NULL;
			stack_ag_p->addr = 0; // all's special address
			stack_ag_p->cnt = 0;
			stack_ag_p->is_comm = false;
		}

		bpf_map_lookup_elem(sample_fd, cur_key, &sample_time);

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->stack_id, frame);
		if (DEBUG && err) {
			printf("\n[user stack lost]\n");
		} else {
			if (pids_i < MAX_PID && *pid_nr && !find_pid(pids, cur_key->tgid, pids_i)) {
				pids[pids_i++] = cur_key->tgid;
				qsort(pids, pids_i, sizeof(int), compar);
			}

			stack_ag_p->cnt += sample_time;
			stack_insert(stack_ag_p, frame, sample_time, MAX_STACK_DEPTH);
			++cnt;
		}

		last_key = cur_key;
	} 

	*pid_nr = pids_i;

	printf("\nCollected %llu samples\n", cnt);

	free(frame);
	return stack_ag_p;
}

struct stack_ag* stack_aggre(struct bpf_map *stack_map, struct bpf_map *sample, int *pids, int *pid_nr)
{
	struct stack_ag *stack_ag_p = NULL;

	int stack_map_fd = bpf_map__fd(stack_map);
	int sample_fd = bpf_map__fd(sample);
	int err, pids_i = 0;

	struct key_t a = {}, b = {};
	struct key_t *last_key = &a;
	struct key_t *cur_key = &b;

	unsigned long long *frame = calloc(MAX_STACK_DEPTH, 
					   sizeof(unsigned long long)), 
		      		    sample_num = 0,
				    cnt = 0;

	/*
	 * root
	 * |_ child1(comm1)___ child2(comm2)___ child3(comm3)
	 *      |_child11(sym11)     |_child21(sym21)
	 */

	while (bpf_map_get_next_key(sample_fd, last_key, cur_key) == 0) {
		if (stack_ag_p == NULL) {
			/* initialize root stack aggregation pointer */
			stack_ag_p = malloc(sizeof(struct stack_ag));
			stack_ag_p->next = NULL;
			stack_ag_p->child = NULL;
			stack_ag_p->addr = 0; // all's special address
			stack_ag_p->cnt = 0;
			stack_ag_p->is_comm = false;
		}

		bpf_map_lookup_elem(sample_fd, cur_key, &sample_num);

		/* stack frame */
		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->kstack_id, frame);
		/* kernel stack not available */
		if (cur_key->kstack_id != -EFAULT) {
			if (DEBUG && err)
				printf("\n[kernel stack lost]\n");
			else {
				stack_ag_p->cnt += sample_num;
				stack_insert(stack_ag_p, frame, sample_num, MAX_STACK_DEPTH);
				++cnt;
			}
		}

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->ustack_id, frame);
		if (DEBUG && err)
			printf("\n[user stack lost]\n");
		else {
			if (pids_i < MAX_PID && *pid_nr && !find_pid(pids, cur_key->pid, pids_i)) {
				pids[pids_i++] = cur_key->pid;
				qsort(pids, pids_i, sizeof(int), compar);
			}

			stack_ag_p->cnt += sample_num;
			stack_insert(stack_ag_p, frame, sample_num, MAX_STACK_DEPTH);
			++cnt;
		}

		last_key = cur_key;
	} 

	*pid_nr = pids_i;

	printf("\nCollected %llu samples\n", cnt);

	free(frame);
	return stack_ag_p;
}

// struct stack_ag *comm_lookup_insert(struct stack_ag *stack_ag_p, char* comm)
// {
// 	struct stack_ag *p, *pp, *q, *p_parent;
// 	p = stack_ag_p->child;
// 	p_parent = stack_ag_p;
// 	pp = p;
// 	q = NULL;
// 
// 	int flag = 0;
// 
// 	/* if command doesn't match, add a new one */
// 	while (pp) {
// 		if (strcmp(pp->comm, comm) == 0) {
// 			p_parent = pp;
// 			flag = 1;
// 			break;
// 		}
// 		q = pp;
// 		pp = pp->next;
// 	}
// 
// 	if (!flag) {
// 		struct stack_ag *tmp = malloc(sizeof(struct stack_ag));
// 		if (tmp == NULL) {
// 			return NULL;
// 		}
// 
// 		tmp->next = NULL;
// 		tmp->addr = 0;
// 		tmp->child = NULL;
// 		strcpy(tmp->comm, comm);
// 		tmp->cnt = 0;
// 		tmp->is_comm = true;
// 
// 		if (q) {
// 			q->next = tmp;
// 		} else {
// 			p_parent->child = tmp;
// 		}
// 		p_parent = tmp;
// 	}
// 
// 	return p_parent;
// }

int stack_insert(struct stack_ag* stack_ag_p, unsigned long long* frame, unsigned long long sample_num, int frame_sz)
{
	int err = 0;

	if (stack_ag_p == NULL) {
		printf("No stacks sample found\n");
		err = -1;
		goto return_err;
	}

	struct stack_ag *p = stack_ag_p;
	int index = 0;
	struct stack_ag *p_parent = NULL;

	/* root frame */
	p->cnt += sample_num;

	/* every stack frame is a child of root */
	p_parent = p;
	p = p->child;

	// move index to end
	for (;frame[index] && index < frame_sz;index++) {}
	--index;

	/* add count for the existed prefix */
	while (p && index >= 0) {
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
			tmp->addr = frame[index];
			tmp->cnt = sample_num;
			tmp->is_comm = false;
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
		struct stack_ag *tmp = malloc(sizeof(struct stack_ag));
		if (tmp == NULL) {
			err = -1;
			goto return_err;
		}

		tmp->next = NULL;
		tmp->child = NULL;
		tmp->addr = frame[index];
		tmp->cnt = sample_num;
		tmp->is_comm = false;

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

static unsigned depth = 1;

void stack_get_depth_prvt(struct stack_ag* p, unsigned d)
{
	if (p == NULL) {
		depth = max(depth, d - 1);
		return;
	}
	stack_get_depth_prvt(p->child, d + 1);
	stack_get_depth_prvt(p->next, d);
}

int stack_get_depth(struct stack_ag* p)
{
	depth = 1;
	stack_get_depth_prvt(p, depth);
	return depth;
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
