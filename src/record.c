/*-*- coding:utf-8                                                          -*-│
│vi: set net ft=c ts=4 sts=4 sw=4 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2023 Howard Chu                                                    │
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

#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <linux/perf_event.h>
#include <stdbool.h>

#include <sys/syscall.h>
/* TODO: portable? */
#define __USE_MISC
#define _GNU_SOURCE
#include <unistd.h>

#include "sub_commands.h"
#include "util.h"
#include "record.skel.h"
#include "record.h"
#include "sym.h"

/* kernel symbol table */
const struct ksyms* ksym_tb;
/* user symbol table */
const struct usyms* usym_tb;

static void signalHandler(int signum)
{
}

int print_stack_frame(unsigned long long *frame, char mode)
{
	char name[128];
	if (mode == 'k') {
		printf("[kernel]:\n");
		for (size_t i = 0; frame[i] && i < PERF_MAX_STACK_DEPTH; i++) {
			printf("  %lx\n", frame[i]);
		}
	} else if (mode == 'u') {
		printf("[user]:\n");
		for (size_t i = 0; frame[i] && i < PERF_MAX_STACK_DEPTH; i++) {
			usym_addr_to_sym(usym_tb, frame[i], name);
			printf("  %lx %s\n", frame[i], name);
		}
	}
	printf("\n");
	return 0;
}

void print_stack(struct bpf_map *stack_map, struct bpf_map *sample)
{
	int stack_map_fd = bpf_map__fd(stack_map);
	int sample_fd = bpf_map__fd(sample);

	// empty
	struct key_t a = {}, b = {};
	struct key_t *last_key = &a;
	struct key_t *cur_key = &b;

	unsigned long long *frame = calloc(PERF_MAX_STACK_DEPTH, sizeof(unsigned long long));
	int err;

	int db = 0;

	while (bpf_map_get_next_key(sample_fd, last_key, cur_key) == 0) {

		/* stack frame */
		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->kern_stack_id, frame);
		/* kernel stack not available */
		if (cur_key->kern_stack_id != -EFAULT) {
			if (err)
				printf("\n[kernel stack lost]\n");
			else
				print_stack_frame(frame, 'k');
		}

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->user_stack_id, frame);
		if (err)
			printf("\n[user stack lost]\n");
		else
			print_stack_frame(frame, 'u');

		last_key = cur_key;
	} 
}

int split(char *str, pid_t *pids) {
	char *token;
	pid_t pid;
	size_t index = 0;
	token = strtok(str, ",");
	while( token != NULL && index < MAX_PID) {
		pid = atoi(token);
		if (pid != 0)
			pids[index++] = pid;
		token = strtok(NULL, ",");
	}
	return index;
}

int cmd_record(int argc, char **argv)
{
	// TODO: stoi illegal
	if (argc < 3) {
		char prompt[] = "\n  Usage:\n"
		                "\n    sberf record <PID>\n\n";
		printf("%s", prompt);
		return 0;
	}

	struct record_bpf *skel;
	int err;

	skel = record_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* pids to trace */
	pid_t *pids = skel->bss->pids;
	size_t num_of_pids = split(argv[2], pids);
	// TODO: could be false
	skel->bss->spec_pid = true;

	unsigned long long freq = 1;
	// TODO: parse command
	unsigned long long sample_freq = 1; 

	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = freq,
		.sample_freq = sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	// TODO: change value
	bpf_map__set_value_size(skel->maps.stack_map, PERF_MAX_STACK_DEPTH * sizeof(unsigned long long));
	bpf_map__set_max_entries(skel->maps.stack_map, MAX_ENTRIES);


	err = record_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	int fd;
	struct bpf_link* link;
	/* open on any cpu */
	for (size_t i = 0;i < num_of_pids; i++) {
		fd = syscall(__NR_perf_event_open, &attr, pids[i], -1, -1, PERF_FLAG_FD_CLOEXEC);
		if (fd < 0) {
			printf("Failed to open perf event for pid %d\n", pids[i]);
		}
		link =  bpf_program__attach_perf_event(skel->progs.profile, fd);
		if (link == NULL) {
			printf("Failed to attach bpf program for pid %d\n", pids[i]);
			goto cleanup;
		}
	}

	err = record_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* consume sigint */
	signal(SIGINT, signalHandler);

	// TODO: parse command
	sleep(100);

	/* load symbol table */
	ksym_tb = ksym_load();
	usym_tb = usym_load(pids, num_of_pids);

	if (ksym_tb && usym_tb)
		printf("\nSymbols loaded\n");

	print_stack(skel->maps.stack_map, skel->maps.sample);

cleanup:
	record_bpf__destroy(skel);

	return 0;
}
