/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#include <bpf/bpf.h>
#include <stdbool.h>
#include <stdlib.h>
#include "stack.h"
#include "record.skel.h"
#include "record.h" /* for key_t */
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

struct stack_ag* stack__find_comm(struct stack_ag *root, struct comm_arr *comms, pid_t pid)
{
	struct stack_ag *comm_sections, *pre, *cur;
	char *comm = comm__find_by_pid(comms, pid);
	if (comm == NULL) {
		printf("Cannot find the command of pid %d", pid);
		return NULL;
	}

	/* If this command doesn't exist, create one */
	if (root == NULL)
		return NULL;

	comm_sections = root->child;
	if (comm_sections == NULL) {
		root->child = malloc(sizeof(struct stack_ag));
		if (root->child == NULL) {
			printf("Failed to create the first command for stack aggregation\n");
			return NULL;
		}

		comm_sections = root->child;
		memset(comm_sections, 0, sizeof(struct stack_ag));

		comm_sections->is_comm = true;
		comm_sections->pid = pid;
		strcpy(comm_sections->comm, comm);
	}

	pre = NULL;
	cur = comm_sections;

	while (cur) {
		if (cur->pid == pid)
			break;

		pre = cur;
		cur = cur->next;
	}

	if (cur == NULL && pre) {
		pre->next = malloc(sizeof(struct stack_ag));
		if (pre->next == NULL) {
			printf("Failed to create a new command section for stack aggregation\n");
			return NULL;
		}

		cur = pre->next;

		memset(cur, 0, sizeof(struct stack_ag));

		cur->is_comm = true;
		cur->pid = pid;
		strcpy(cur->comm, comm);
	}

	return cur;
}

struct stack_ag* stack_aggre_off_cpu(struct bpf_map *stack_map, struct bpf_map *sample, struct comm_arr *comms)
{
	struct stack_ag *root = NULL;

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
		if (root == NULL) {
			/* initialize root stack aggregation pointer */
			root = malloc(sizeof(struct stack_ag));
			root->next = NULL;
			root->child = NULL;
			root->addr = 0; /* a node named "all" has an address of 0 */
			root->cnt = 0;
			root->is_comm = false;
		}

		bpf_map_lookup_elem(sample_fd, cur_key, &sample_time);

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->stack_id, frame);
		if (DEBUG && err) {
			printf("\n[user stack lost]\n");
		} else {
			root->cnt += sample_time;
			stack_insert(root, frame, sample_time, MAX_STACK_DEPTH);
			++cnt;
		}

		last_key = cur_key;
	} 

	printf("\nCollected %llu samples\n", cnt);

	free(frame);
	return root;
}

struct stack_ag* stack_aggre(struct bpf_map *stack_map, struct bpf_map *sample, struct comm_arr *comms)
{
	struct stack_ag *root = NULL, *comm_entry;

	int stack_map_fd = bpf_map__fd(stack_map);
	int sample_fd = bpf_map__fd(sample);
	int err, pids_i = 0;

	struct key_t a = {}, b = {};
	struct key_t *last_key = &a;
	struct key_t *cur_key = &b;

	unsigned long long *frame = calloc(MAX_STACK_DEPTH, sizeof(unsigned long long)),
					   sample_num = 0, cnt = 0;

	/*
	 * root
	 * |_ child1(comm1)___ child2(comm2)___ child3(comm3)
	 *      |_child11(sym11)     |_child21(sym21)
	 */
	// TODO: rewrite everything about comm

	while (bpf_map_get_next_key(sample_fd, last_key, cur_key) == 0) {
		if (root == NULL) {
			/* initialize root stack aggregation pointer */
			root = malloc(sizeof(struct stack_ag));
			root->next = NULL;
			root->child = NULL;
			root->addr = 0; // all's special address
			root->cnt = 0;
			root->is_comm = false;
		}

		bpf_map_lookup_elem(sample_fd, cur_key, &sample_num);

		/* stack frame */
		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->kstack_id, frame);
		if (cur_key->kstack_id != -EFAULT) {
			if (DEBUG && err)
				printf("\n[kernel stack lost]\n");
			else {
				root->cnt += sample_num;
				stack_insert(root, frame, sample_num, MAX_STACK_DEPTH);
				++cnt;
			}
		}

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->ustack_id, frame);
		if (DEBUG && err)
			printf("\n[user stack lost]\n");
		else {
			root->cnt += sample_num;

			comm_entry = stack__find_comm(root, comms, cur_key->pid);
			if (comm_entry == NULL)
				return NULL;

			stack_insert(comm_entry, frame, sample_num, MAX_STACK_DEPTH);
			++cnt;
		}

		last_key = cur_key;
	} 

	printf("\nCollected %llu samples\n", cnt);

	free(frame);
	return root;
}

int stack_insert(struct stack_ag* root, unsigned long long* frame, unsigned long long sample_num, int frame_sz)
{
	int err = 0;

	if (root == NULL) {
		printf("No stacks sample found\n");
		err = -1;
		goto return_err;
	}

	struct stack_ag *p = root;
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

void __stack_get_depth(struct stack_ag* p, unsigned d)
{
	if (p == NULL) {
		depth = max(depth, d - 1);
		return;
	}
	__stack_get_depth(p->child, d + 1);
	__stack_get_depth(p->next, d);
}

int stack_get_depth(struct stack_ag* p)
{
	depth = 1;
	__stack_get_depth(p, depth);
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
