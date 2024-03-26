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

#include "cli.h"
#include "sub_commands.h"
#include "util.h"
#include "record.skel.h"
#include "stat.skel.h"
#include "mem.skel.h"
#include "record.h"
#include "stack.h"
#include "sym.h"
#include "plot.h"

/* kernel symbol table */
struct ksyms* ksym_tb;
/* user symbol table */
struct usyms* usym_tb;

static char event_names[48][48];

static struct {
	int freq;
	unsigned long long sample_freq; 
	int no_plot;
	int rec_all;
	char pids[256];
	int all_p;
	char svg_file_name[256];
	char event_names_str[512];
} env = {
	.freq = 1,
	.sample_freq = 69,
	.no_plot = 0,
	.pids = "\0", 
	.all_p = 0,
	.svg_file_name = "debug.svg",
	.event_names_str = "\0",
};

static struct func_struct record_func[] = {
	{"-s", record_syscall},
	{"-t", record_tracepoint},
	{"-p", record_pid},
	{"-m", record_mem},
};

static struct env_struct record_env[] = {
	{"-f", 0, &env.sample_freq},
	{"-np", 4, &env.no_plot},
	{"-a", 4, &env.all_p},
	{"-p", 1, &env.pids},
	{"-fn", 1, &env.svg_file_name},
};

static struct env_struct event_env[] = {
	{"-p", 1, &env.pids},
	{"-s", 1, &env.event_names_str},
	{"-t", 1, &env.event_names_str},
	{"-rt", 1, &env.event_names_str},
};

static struct env_struct mem_env[] = {
	{"-f", 0, &env.sample_freq},
	{"-np", 4, &env.no_plot},
	{"-a", 4, &env.all_p},
	{"-p", 1, &env.pids},
	{"-fn", 1, &env.svg_file_name},
};

static void signalHandler(int signum)
{
}

int print_stack_frame(unsigned long long *frame, int sample_num, char mode)
{
	char name[128];
	if (mode == 'k') {
		printf("[kernel] %d samples:\n", sample_num);
		for (int i = 0; frame[i] && i < MAX_STACK_DEPTH; i++) {
			ksym_addr_to_sym(ksym_tb, frame[i], name);
			printf("  %lx %s\n", frame[i], name);
		}
	} else if (mode == 'u') {
		printf("[user] %d samples:\n", sample_num);
		for (int i = 0; frame[i] && i < MAX_STACK_DEPTH; i++) {
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

	unsigned long long *frame = calloc(MAX_STACK_DEPTH, sizeof(unsigned long long));
	int err;

	int sample_num = 0;
	int sample_num_total = 0;

	while (bpf_map_get_next_key(sample_fd, last_key, cur_key) == 0) {

		/* number of stack sample */
		err = bpf_map_lookup_elem(sample_fd, cur_key, &sample_num);
		if (err) {
			printf("Failed to retrieve number of stack sample\n");
			sample_num = 0;
		}

		sample_num_total += sample_num;

		/* stack frame */
		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->kern_stack_id, frame);
		/* kernel stack not available */
		if (cur_key->kern_stack_id != -EFAULT) {
			if (err)
				printf("\n[kernel stack lost]\n");
			else
				print_stack_frame(frame, sample_num, 'k');
		}

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->user_stack_id, frame);
		if (err)
			printf("\n[user stack lost]\n");
		else
			print_stack_frame(frame, sample_num, 'u');

		last_key = cur_key;
	} 
	
	printf("Collected %d samples\n", sample_num_total);
}

int split_event_str() {
	char *token;
	size_t index = 0;
	token = strtok(env.event_names_str, ",");
	while( token != NULL && index < ARRAY_LEN(event_names)) {
		strcpy(event_names[index++], token);
		token = strtok(NULL, ",");
	}
	return index;
}

int split(char *str, pid_t *pids) {
	char *token;
	pid_t pid;
	size_t index = 0;
	token = strtok(str, ",");
	while( token != NULL && index < MAX_PID) {
		pid = atoi(token);
		if (!(pid == 0 && strcmp(token, "0") != 0))
			pids[index++] = pid;
		token = strtok(NULL, ",");
	}
	return index;
}

int record_plot(struct bpf_map* stack_map, struct bpf_map* sample, int *pids, int num_of_pids) {
	/* aggregate stack samples */
	struct stack_ag* stack_ag_p = stack_aggre(stack_map, sample);

	if (stack_ag_p == NULL) {
		printf("No stack data\n");
		return -1;
	}

	/* plot the aggregated stack */
	if(plot(stack_ag_p, env.svg_file_name, pids, num_of_pids)) {
		printf("Failed to plot");
		return -1;
	} else {
		printf("\nPlotted to %s\n", env.svg_file_name);
	}

	/* free stack */
	stack_free(stack_ag_p);
}

int cmd_record(int argc, char **argv)
{
	if (argc < 3) {
		char help[] = "\n  Usage:\n"
	                  "\n    sberf record <PID>\n\n";
		printf("%s", help);
		return 0;
	}

	int err = 0;
	int cur = 2;

	int (*funcp)(int, char**, int) = parse_opts_func(argc, argv, cur, record_func, ARRAY_LEN(record_func));

	if (funcp) {
		err = funcp(argc, argv, cur);
	} else { // default is to record pids
		err = record_pid(argc, argv, cur);
	}
	return err;
}

int record_syscall(int argc, char** argv, int cur)
{
	struct stat_bpf *skel;
	int err = 0;

	parse_opts_env(argc, argv, cur, event_env, ARRAY_LEN(event_env));

	int event_num = split_event_str();

	printf("recording events: ");
	for (int i = 0;i < event_num; i++)
		printf("%s ", event_names[i]);
	printf("\n");

	skel = stat_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	err = stat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = stat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* syscall */
	struct bpf_link *link = NULL;
	for (int i = 0;i < event_num;i++) {
		link = bpf_program__attach_ksyscall(skel->progs.stat_ksyscall, event_names[i], NULL);
		if (link == NULL) {
			printf("Failed to attach syscall %s\n", event_names[i]);
		}
	}

	sleep(100);

cleanup:
	stat_bpf__destroy(skel);
	return err;
}

int record_tracepoint(int argc, char** argv, int cur)
{
	struct stat_bpf *skel;
	int err = 0;

	parse_opts_env(argc, argv, cur, event_env, ARRAY_LEN(event_env));

	int event_num = split_event_str();

	printf("recording events: ");
	for (int i = 0;i < event_num; i++)
		printf("%s ", event_names[i]);
	printf("\n");

	skel = stat_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	err = stat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = stat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	struct bpf_link *link = NULL;
	for (int i = 0;i < event_num;i++) {
		/* syscalls:sys_enter_open */
		char *tracepoint;
		size_t index = 0;

		/* event_names[i] now is the category(syscalls), tracepoint is sys_enter_open */
		strtok(event_names[i], ":"); tracepoint = strtok(NULL, ":");

		link = bpf_program__attach_tracepoint(skel->progs.stat_tracepoint, event_names[i], tracepoint);
		if (link == NULL) {
			printf("Failed to attach syscall %s\n", event_names[i]);
		}
	}

	sleep(100);

cleanup:
	stat_bpf__destroy(skel);
	return err;
}

int record_pid(int argc, char** argv, int cur)
{
	struct record_bpf *skel;
	int err = 0;

	parse_opts_env(argc, argv, cur, record_env, ARRAY_LEN(record_env));

	skel = record_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	/* pids to trace */
	pid_t *pids = skel->bss->pids;
	size_t num_of_pids = split(env.pids, pids);
	skel->bss->spec_pid = !env.all_p; // if to record all process(all_p = 1), specific pid(spec_pid) is 0

	/* sberf record 1001 is also legal */
	if (!env.all_p && strlen(env.pids) == 0) {
		num_of_pids = split(argv[2], pids);
	}

	unsigned long long freq = env.freq;
	// TODO: parse command
	unsigned long long sample_freq = env.sample_freq; 

	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = freq,
		.sample_freq = sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	// TODO: change value
	bpf_map__set_value_size(skel->maps.stack_map, MAX_STACK_DEPTH * sizeof(unsigned long long));
	bpf_map__set_max_entries(skel->maps.stack_map, MAX_ENTRIES);

	err = record_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	int fd;
	struct bpf_link* link;
	/* open on any cpu */
	for (int i = 0;i < num_of_pids; i++) {
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

	/* record all process */
	if (env.all_p){ 
		// TODO: all cpu
		int cpu_cnt = 1;
		for (int i = 0;i < cpu_cnt;i++) {
			fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, PERF_FLAG_FD_CLOEXEC);
			if (fd < 0) {
				printf("Failed to open perf event for all process\n");
			}
			link =  bpf_program__attach_perf_event(skel->progs.profile, fd);
			if (link == NULL) {
				printf("Failed to attach bpf program for all process\n");
				goto cleanup;
			}
		}
	}

	err = record_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (!env.all_p) {
		printf("recording pids: ");
		for (int i = 0; i < num_of_pids; i++)
			printf("%d ", pids[i]);
	} else {
		printf("recording all processes ");
	}
	printf("in %d HZ\n", env.sample_freq);

	/* consume sigint */
	signal(SIGINT, signalHandler);

	// TODO: parse command
	sleep(100);

	/* load symbol table */
	if (env.no_plot == 1) {
		/* doesn't plot, just print */
		ksym_tb = ksym_load();
		usym_tb = usym_load(pids, num_of_pids);

		if (ksym_tb && usym_tb)
			printf("\nSymbols loaded\n");

		print_stack(skel->maps.stack_map, skel->maps.sample);

		ksym_free(ksym_tb);
		usym_free(usym_tb);

	} else if (env.no_plot == 0){
		/* plot */
		record_plot(skel->maps.stack_map, skel->maps.sample, pids, num_of_pids);
	}

cleanup:
	record_bpf__destroy(skel);
	return err;
}

int record_mem(int argc, char** argv, int cur)
{
	struct mem_bpf *skel;
	int err = 0;

	parse_opts_env(argc, argv, cur, mem_env, ARRAY_LEN(record_env));

	skel = mem_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	/* pids to trace */
	pid_t *pids = skel->bss->pids;
	size_t num_of_pids = split(env.pids, pids);
	skel->bss->spec_pid = !env.all_p; // if to record all process(all_p = 1), specific pid(spec_pid) is 0

	struct bpf_link *link = NULL;
	link = bpf_program__attach_ksyscall(skel->progs.mem_profile, "mmap", NULL);

	err = mem_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = mem_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}


	sleep(100);

cleanup:
	mem_bpf__destroy(skel);
	return err;
	return 0;
}
