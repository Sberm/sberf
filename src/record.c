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
#define __USE_MISC
#define _GNU_SOURCE
#include <unistd.h>

#include "cli.h"
#include "sub_commands.h"
#include "util.h"

#include "record.skel.h"
#include "event.skel.h"
#include "mem.skel.h"
#include "off_cpu.skel.h"

#include "record.h"
#include "stack.h"
#include "sym.h"
#include "plot.h"
#include "event.h"
#include "off_cpu.h"

#define TP_TRGR_PROG(index) skel->progs.tp_trgr_##index
#define MAX_TP_TRGR_PROG 10

/* global variables for perf poll */
static struct ksyms *record__ksym_tb;
static struct usyms *record__usym_tb;

static char event_names[MAX_TP_TRGR_PROG][64];
static volatile bool done;

static struct {
	int freq;
	unsigned long long sample_freq; 
	int no_plot;
	int rec_all;
	char pids[256];
	int all_p;
	char svg_file_name[256];
	char event_names_str[512];
	bool debug;
} env = {
	.freq = 1,
	.sample_freq = 69,
	.no_plot = 0,
	.pids = "\0", 
	.all_p = false,
	.svg_file_name = "debug.svg",
	.event_names_str = "\0",
	.debug = false,
};

static struct func_struct record_func[] = {
	{"-s", record_syscall},
	{"--syscall", record_syscall},
	{"-t", record_tracepoint},
	{"--tracepoint", record_tracepoint},
	{"-p", record_pid},
	{"--pid", record_pid},
	{"-m", record_mem},
	{"--memory", record_mem},
	{"-op", record_off_cpu},
	{"--off-cpu", record_off_cpu},
	{"-h", record_print_help},
	{"--help", record_print_help},
	{"--numa", record_numa},
	{"-hw", record_hardware},
	{"--hardware", record_hardware},
};

// TODO: refactor, delete the duplicates
// TODO: change them to enums
static struct env_struct pid_env[] = {
	{"-f", 0, &env.sample_freq},
	{"-np", 4, &env.no_plot},
	{"-a", 4, &env.all_p},
	{"-p", 1, &env.pids},
	{"-o", 1, &env.svg_file_name},
};

static struct env_struct event_env[] = {
	{"-f", 0, &env.sample_freq},
	{"-np", 4, &env.no_plot},
	{"-a", 4, &env.all_p},
	{"-p", 1, &env.pids},
	{"-o", 1, &env.svg_file_name},
	{"-s", 1, &env.event_names_str},
	{"-t", 1, &env.event_names_str},
};

static struct env_struct mem_env[] = {
	{"-f", 0, &env.sample_freq},
	{"-np", 4, &env.no_plot},
	{"-a", 4, &env.all_p},
	{"-p", 1, &env.pids},
	{"-o", 1, &env.svg_file_name},
};

static struct env_struct off_cpu_env[] = {
	{"-f", 0, &env.sample_freq},
	{"-np", 4, &env.no_plot},
	{"-a", 4, &env.all_p},
	{"-p", 1, &env.pids},
	{"-o", 1, &env.svg_file_name},
};

struct tp_name {
	char category[16];
	char name[48];
};

static void signalHandler(int signum)
{
	done = true;
}

// TODO: use enum
int print_stack_frame(unsigned long long *frame, unsigned long long sample_num, char mode, void* sym_tb)
{
	char name[128];
	if (mode == 'k') {
		printf("[kernel] %lu samples:\n", sample_num);
		for (int i = 0; frame[i] && i < MAX_STACK_DEPTH; i++) {
			ksym_addr_to_sym((struct ksyms*)sym_tb, frame[i], name);
			printf("  %lx %s\n", frame[i], name);
		}
	} else if (mode == 'u') {
		printf("[user] %lu samples:\n", sample_num);
		for (int i = 0; frame[i] && i < MAX_STACK_DEPTH; i++) {
			usym_addr_to_sym((struct usyms*)sym_tb, frame[i], name);
			printf("  %lx %s\n", frame[i], name);
		}
	} else if (mode == 'o') {
		printf("[off-cpu] %.5fms:\n", (double)sample_num / 1000000UL);
		int i = 0;
		for (; frame[i] && i < MAX_STACKS; i++) {
			usym_addr_to_sym((struct usyms*)sym_tb, frame[i], name);
			printf("  %lx %s\n", frame[i], name);
		}
	}
	printf("\n");
	return 0;
}

void print_stack(struct bpf_map *stack_map, struct bpf_map *sample, struct ksyms* ksym_tb, struct usyms* usym_tb)
{
	int stack_map_fd = bpf_map__fd(stack_map);
	int sample_fd = bpf_map__fd(sample);

	// empty
	struct key_t a = {}, b = {};
	struct key_t *last_key = &a;
	struct key_t *cur_key = &b;

	unsigned long long *frame = calloc(MAX_STACK_DEPTH, sizeof(unsigned long long));
	int err;

	unsigned long long sample_num = 0, sample_num_total = 0;

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
				print_stack_frame(frame, sample_num, 'k', ksym_tb);
		}

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->user_stack_id, frame);
		if (err)
			printf("\n[user stack lost]\n");
		else
			print_stack_frame(frame, sample_num, 'u', usym_tb);

		last_key = cur_key;
	} 

	free(frame);

	printf("Collected %d samples\n", sample_num_total);
}

void print_stack_off_cpu(struct bpf_map *stack_map, struct bpf_map *off_cpu_data, struct ksyms* ksym_tb, struct usyms* usym_tb)
{
	int stack_map_fd = bpf_map__fd(stack_map);
	int off_cpu_data_fd = bpf_map__fd(off_cpu_data);
	struct off_cpu_key a;
	struct off_cpu_key *last_key = NULL, *cur_key = &a;
	int err;
	unsigned long long data;
	unsigned int sample_num_total = 0;
	unsigned long long *frame = calloc(MAX_STACKS, sizeof(unsigned long long));

	while (bpf_map_get_next_key(off_cpu_data_fd, last_key, cur_key) == 0) {
		/* number of stack sample */
		err = bpf_map_lookup_elem(off_cpu_data_fd, cur_key, &data);
		if (err) {
			printf("Failed to retrieve off-cpu data\n");
		}

		++sample_num_total;

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->stack_id, frame);
		if (err && env.debug) {
			printf("Failed to print off-cpu samples\n");
		} else {
			printf("PID %d\n", cur_key->tgid);
			print_stack_frame(frame, data, 'o', usym_tb);
		}

		last_key = cur_key;
	} 

	free(frame);

	printf("Collected %d off-cpu samples\n", sample_num_total);
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

int split_pid(char *str, pid_t *pids) {
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

int record_plot_off_cpu(struct bpf_map* stack_map, struct bpf_map* off_cpu_time, int *pids, int pid_nr) {
	/* aggregate stack samples */
	struct stack_ag* stack_ag_p = stack_aggre_off_cpu(stack_map, off_cpu_time);

	if (!stack_ag_p) {
		printf("No stack data\n");
		return -1;
	}

	if(plot_off_cpu(stack_ag_p, env.svg_file_name, pids, pid_nr)) {
		printf("Failed to plot");
		return -1;
	} else {
		printf("\nPlotted to %s\n", env.svg_file_name);
	}

	stack_free(stack_ag_p);

	return 0;
}

int record_plot(struct bpf_map* stack_map, struct bpf_map* sample, int *pids, int pid_nr) {
	/* aggregate stack samples */
	struct stack_ag* stack_ag_p = stack_aggre(stack_map, sample);

	if (!stack_ag_p) {
		printf("No stack data\n");
		return -1;
	}

	/* plot the aggregated stack */
	if(plot(stack_ag_p, env.svg_file_name, pids, pid_nr)) {
		printf("Failed to plot");
		return -1;
	} else {
		printf("\nPlotted to %s\n", env.svg_file_name);
	}

	/* free stack */
	stack_free(stack_ag_p);

	return 0;
}

void __record_print_help()
{
	char help[] = "\n  Usage:\n\n"
	              "    sberf record [options]\n\n"
	              "  Options:\n\n"
	              "    -p[--pid]: Record running time\n"
	              "    -t[--tracepoint]: Record tracepoints' triggered time\n"
	              "    -s[--syscall]: Record stack traces when a syscall is triggered\n"
	              "    -m[--memory]: Record memory usage\n"
	              "    -op[--off-cpu]: Record OFF-CPU time\n"
	              "    -h[--help]: Print this help message\n\n"

	              "    -f: Frequency in Hz\n"
	              "    -np: No plotting, print the stacks instead\n"
	              "    -a: Record all processes\n"
	              "    -o: File name for the plot\n"
	              "\n";

	printf("%s", help);
}

int record_print_help(int argc, char** argv, int index)
{
	__record_print_help();
	return 0;
}

int cmd_record(int argc, char **argv)
{
	if (argc < 3) {
		__record_print_help();
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

/*
void syscall_handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct stack_array *sa = data;
	char name[128];
	for (int i = 0;i < data_sz / sizeof(unsigned long) && sa->array[i];i++) {
		usym_addr_to_sym(record__usym_tb, sa->array[i], name);
		printf("0x%lx %s\n", sa->array[i], name);
	}
	printf("\n");
}
*/

int record_syscall(int argc, char** argv, int index)
{
	return 0;
	/*
	struct event_bpf *skel;
	int err = 0, event_num, fd, one = 1;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};
	size_t pid_nr;
	pid_t pids[MAX_PID];

	parse_opts_env(argc, argv, index, event_env, ARRAY_LEN(event_env));

	pid_nr = split_pid(env.pids, pids);
	if (!pid_nr) {
		__record_print_help();
		return 0;
	}

	event_num = split_event_str();

	if (event_num > 1)
		printf("recording events: ");
	else
		printf("recording event: ");

	for (int i = 0;i < event_num; i++)
		printf("%s ", event_names[i]);
	printf("\n");

	skel = event_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	err = event_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	fd = bpf_map__fd(skel->maps.task_filter);

	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	record__ksym_tb = ksym_load();
	record__usym_tb = usym_load(pids, pid_nr);

	err = event_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8, syscall_handle_event, NULL, NULL, NULL);
	if (pb == NULL)
		goto sym_pb_cleanup;

	struct bpf_link *link = NULL;
	for (int i = 0;i < event_num;i++) {
		link = bpf_program__attach_ksyscall(skel->progs.syscall_trgr, event_names[i], NULL);
		if (link == NULL) {
			printf("Failed to attach syscall %s\n", event_names[i]);
		}
	}

	while (true) {
		err = perf_buffer__poll(pb, 200);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0)
			goto cleanup;
	}

	signal(SIGINT, signalHandler);

	for(;!done;){};

sym_pb_cleanup:
	ksym_free(record__ksym_tb);
	usym_free(record__usym_tb);
	perf_buffer__free(pb);

cleanup:
	event_bpf__destroy(skel);
	return err;
	*/
}

int record_tracepoint(int argc, char** argv, int index)
{
	struct event_bpf *skel;
	struct bpf_link *link = NULL;
	struct bpf_tracepoint_opts tp_opts = {.sz = sizeof(struct bpf_tracepoint_opts)};
	struct tp_name tp_names[MAX_TP_TRGR_PROG];
	int err = 0, event_num = 0, fd, one = 1;
	unsigned long long cnt = 0;
	pid_t pids[MAX_PID];
	size_t pid_nr;
	char tmp[64];

	parse_opts_env(argc, argv, index, event_env, ARRAY_LEN(event_env));

	event_num = split_event_str();

	pid_nr = split_pid(env.pids, pids);
	if (!pid_nr && !env.all_p) {
		__record_print_help();
		return 0;
	}

	printf("recording events: ");
	for (int i = 0;i < event_num; i++)
		printf("%s ", event_names[i]);
	printf("\n");

	skel = event_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	err = event_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	struct bpf_program *tp_trigger_prog[MAX_TP_TRGR_PROG] = {
		TP_TRGR_PROG(0),
		TP_TRGR_PROG(1),
		TP_TRGR_PROG(2),
		TP_TRGR_PROG(3),
		TP_TRGR_PROG(4),
		TP_TRGR_PROG(5),
		TP_TRGR_PROG(6),
		TP_TRGR_PROG(7),
		TP_TRGR_PROG(8),
		TP_TRGR_PROG(9),
	};

	if (env.all_p)
		skel->bss->spec_pid = false;
	else
		skel->bss->spec_pid = true;

	/* task filter */
	fd = bpf_map__fd(skel->maps.task_filter);

	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	for (int i = 0; i < event_num && i < MAX_TP_TRGR_PROG; i++) {
		/* syscalls:sys_enter_open */
		char *tracepoint;
		size_t index = 0;

		/* event_names[i] now is the category(syscalls), tracepoint is sys_enter_open */
		strtok(event_names[i], ":"); tracepoint = strtok(NULL, ":");

		strcpy(tp_names[i].category, event_names[i]);
		strcpy(tp_names[i].name, tracepoint);

		link = bpf_program__attach_tracepoint(tp_trigger_prog[i], event_names[i], tracepoint);
		if (link == NULL) {
			printf("Failed to attach tracepoint %s:%s\n", event_names[i], tracepoint);
		}
	}
	
	err = event_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	skel->bss->enable = true;

	signal(SIGINT, signalHandler);

	for(;!done;){};

	skel->bss->enable = false;

	printf("\n");
	printf("    %-46s    %s\n\n", "event", "count");

	fd = bpf_map__fd(skel->maps.event_cnt);
	if (fd < 0) {
		printf("Failed to find fd of event counting map\n");
		goto cleanup;
	}

	for (unsigned int i = 0; i < event_num && i < MAX_TP_TRGR_PROG; i++) {
		err = bpf_map_lookup_elem(fd, &i, &cnt);
		if (err)
			cnt = 0;

		sprintf(tmp, "%s:%s", tp_names[i].category, tp_names[i].name);
		printf("    %-46s    %u\n", tmp, cnt);
	}

	printf("\n");

cleanup:
	event_bpf__destroy(skel);
	return err;
}

int record_pid(int argc, char** argv, int index)
{
	struct record_bpf *skel;
	int err = 0, one = 1, fd;
	struct bpf_link* link;
	size_t pid_nr;
	unsigned long long freq, sample_freq;
	struct ksyms* ksym_tb;
	struct usyms* usym_tb;
	pid_t pids[MAX_PID];
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	parse_opts_env(argc, argv, index, pid_env, ARRAY_LEN(pid_env));

	skel = record_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	pid_nr = split_pid(env.pids, pids);

	/* sberf record 1001 is also legal */
	if (!env.all_p && strlen(env.pids) == 0)
		pid_nr = split_pid(argv[2], pids);

	if (!env.all_p && !pid_nr) {
		__record_print_help();
		return 0;
	}

	/* update task_filter */
	fd = bpf_map__fd(skel->maps.task_filter);

	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	freq = env.freq;
	sample_freq = env.sample_freq; 

	attr.freq = freq;
	attr.sample_freq = sample_freq;

	// TODO: change value
	bpf_map__set_max_entries(skel->maps.stack_map, MAX_ENTRIES);

	err = record_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
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
			link = bpf_program__attach_perf_event(skel->progs.profile, fd);
			if (link == NULL) {
				printf("Failed to attach bpf program for all process\n");
				goto cleanup;
			}
		}
	} else {
		/* open on any cpu */
		for (int i = 0;i < pid_nr; i++) {
			fd = syscall(__NR_perf_event_open, &attr, pids[i], -1, -1, PERF_FLAG_FD_CLOEXEC);
			if (fd < 0) {
				printf("Failed to open perf event for pid %d\n", pids[i]);
				goto cleanup;
			}
			link =  bpf_program__attach_perf_event(skel->progs.profile, fd);
			if (link == NULL) {
				printf("Failed to attach bpf program for pid %d\n", pids[i]);
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
		printf("Recording pid: ");
		for (int i = 0; i < pid_nr; i++)
			printf("%d ", pids[i]);
	} else {
		printf("Recording all processes ");
	}
	printf("in %d Hz\n", env.sample_freq);

	/* consume sigint */
	signal(SIGINT, signalHandler);

	for (;!done;){}

	if (env.no_plot == 1) {
		ksym_tb = ksym_load();
		usym_tb = usym_load(pids, pid_nr);

		if (ksym_tb && usym_tb)
			printf("\nSymbols loaded\n");

		print_stack(skel->maps.stack_map, skel->maps.sample, ksym_tb, usym_tb);

		ksym_free(ksym_tb);
		usym_free(usym_tb);
	} else if (env.no_plot == 0){
		record_plot(skel->maps.stack_map, skel->maps.sample, pids, pid_nr);
	}

cleanup:
	record_bpf__destroy(skel);
	return err;
}

int record_mem(int argc, char** argv, int index)
{
	struct mem_bpf *skel;
	int err = 0;
	size_t pid_nr;
	pid_t pids[MAX_PID];

	parse_opts_env(argc, argv, index, mem_env, ARRAY_LEN(mem_env));

	skel = mem_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	/* pids to trace */
	pid_nr = split_pid(env.pids, pids);
	if (!pid_nr) {
		__record_print_help();
		return 0;
	}
	
	bpf_map__set_value_size(skel->maps.stack_map, MAX_STACK_DEPTH * sizeof(unsigned long long));
	bpf_map__set_max_entries(skel->maps.stack_map, MAX_ENTRIES);

	err = mem_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	skel->bss->spec_pid = !env.all_p;

	err = mem_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	signal(SIGINT, signalHandler);

	for(;!done;){};

cleanup:
	mem_bpf__destroy(skel);
	return err;
	return 0;
}

int record_off_cpu(int argc, char** argv, int index)
{
	struct off_cpu_bpf *skel;
	struct ksyms *ksym_tb;
	struct usyms *usym_tb;
	int err = 0, pid_nr, one = 1, fd;
	pid_t pids[MAX_PID];

	parse_opts_env(argc, argv, index, off_cpu_env, ARRAY_LEN(off_cpu_env));

	pid_nr = split_pid(env.pids, pids);
	if (!pid_nr && !env.all_p) {
		__record_print_help();
		return 0;
	}

	skel = off_cpu_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	err = off_cpu_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	if (env.all_p)
		skel->bss->spec_pid = false;
	else
		skel->bss->spec_pid = true;

	/* temp */
	if (pid_nr == 0)
		skel->bss->spec_pid = false;

	fd = bpf_map__fd(skel->maps.task_filter);

	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	err = off_cpu_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	skel->bss->enable = true;

	printf("Recording OFF-CPU ");
	for (int i = 0; i < pid_nr; i++)
		printf("%d ", pids[i]);
	printf("\n");

	signal(SIGINT, signalHandler);

	for(;!done;){};

	skel->bss->enable = false;

	if (env.no_plot == 1) {
		ksym_tb = ksym_load();
		usym_tb = usym_load(pids, pid_nr);

		printf("table len %d\n", usym_tb->length);

		if (ksym_tb && usym_tb)
			printf("\nSymbols loaded\n");

		print_stack_off_cpu(skel->maps.stacks, skel->maps.off_cpu_time, ksym_tb, usym_tb);

		ksym_free(ksym_tb);
		usym_free(usym_tb);
	} else if (env.no_plot == 0){
		record_plot_off_cpu(skel->maps.stacks, skel->maps.off_cpu_time, pids, pid_nr);
	}

	return 0;

cleanup:
	off_cpu_bpf__destroy(skel);
	return err;
}

int record_numa(int argc, char** argv, int index)
{
	return 0;
}

int record_hardware(int argc, char** argv, int index)
{
	struct event_bpf *skel;
	int fd, err = 0;
	__u32 zero = 0;
	__u64 cnt;
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	struct bpf_link* link;

	skel = event_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	err = event_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);

	link = bpf_program__attach_perf_event(skel->progs.hardware, fd);
	if (link == NULL) {
		printf("Failed to attach hardware perf event\n");
		goto cleanup;
	}

	err = event_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	skel->bss->enable = true;

	signal(SIGINT, signalHandler);

	for(;!done;){};

	skel->bss->enable = false;

	fd = bpf_map__fd(skel->maps.hw_cnt);
	if (fd < 0) {
		printf("Failed to find fd of hardware counting map\n");
		goto cleanup;
	}

	err = bpf_map_lookup_elem(fd, &zero, &cnt);

	printf("cnt: %llu\n", cnt);

cleanup:
	event_bpf__destroy(skel);
	return err;
}
