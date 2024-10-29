/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <linux/perf_event.h>
#include <stdbool.h>
#include <string.h>

#include <sys/syscall.h>
#include <sys/ioctl.h>
#define _GNU_SOURCE
#include <unistd.h>

#include <time.h>

#include "cli.h"
#include "sub_commands.h"
#include "util.h"

#include "record.skel.h"
#include "event.skel.h"
#include "mem.skel.h"
#include "off_cpu.skel.h"
#include "lock.skel.h"

#include "record.h"
#include "stack.h"
#include "sym.h"
#include "plot.h"
#include "event.h"
#include "off_cpu.h"
#include "comm.h"

#define TP_TRGR_PROG(index) skel->progs.tp_trgr_##index
#define MAX_TP_TRGR_PROG 10 // max tracepoint trigger program

#define LOCK_WAIT "pthread_wait"
#define LIB_PTHREAD "libpthread.so"

/* global variables for perf poll */
static struct ksyms *record__ksym_tb;
static struct usyms *record__usym_tb;

static char event_names[MAX_TP_TRGR_PROG][64];
static volatile bool done;

static struct {
	char pids[256];
	char svg_file_name[256];
	char tmp_str[512];
	char uprobe_symbol[128];
	char object_path[1024];
	unsigned long long sample_freq; 
	int freq;
	int all_p;
	int rec_all;
	bool no_plot;
	bool debug;
	bool collect_stack;
} env = {
	.freq = 1,
	.sample_freq = 69,
	.no_plot = false,
	.pids = "\0", 
	.all_p = false,
	.svg_file_name = "debug.svg",
	.tmp_str = "\0",
	.debug = false,
	.collect_stack = false,
	.object_path = "libc.so.6",
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
	{"-u", record_uprobe},
	{"--uprobe", record_uprobe},
};

#define COMMON_ENV                       \
	{"-f", INT, &env.sample_freq},   \
	{"-np", MGL, &env.no_plot},      \
	{"-a", MGL, &env.all_p},         \
	{"-p", STR, &env.pids},          \
	{"--pid", STR, &env.pids},       \
	{"-o", STR, &env.svg_file_name}, \

static struct env_struct pid_env[] = {
	COMMON_ENV
};

static struct env_struct event_env[] = {
	COMMON_ENV
	{"-s", STR, &env.tmp_str},
	{"--syscall", STR, &env.tmp_str},
	{"-t", STR, &env.tmp_str},
	{"--tracepoint", STR, &env.tmp_str},
	{"-st", MGL, &env.collect_stack},
};

static struct env_struct mem_env[] = {
	COMMON_ENV
};

static struct env_struct off_cpu_env[] = {
	COMMON_ENV
};

static struct env_struct hardware_env[] = {
	COMMON_ENV
	{"-hw", STR, &env.tmp_str},
	{"--hardware", STR, &env.tmp_str},
};

static struct env_struct uprobe_env[] = {
	COMMON_ENV
	{"-u", STR, &env.uprobe_symbol},
	{"--uprobe", STR, &env.uprobe_symbol},
	{"-obj", STR, &env.object_path},
	{"-st", MGL, &env.collect_stack},
};

struct hardware_mapping {
	char type_name[32];
	__u32 type;
};

#define MAX_HARDWARE 16

static struct hardware_mapping hardware_map[] = {
	{"cycles", PERF_COUNT_HW_CPU_CYCLES},
	{"cpu-cycles", PERF_COUNT_HW_CPU_CYCLES},
	{"instructions", PERF_COUNT_HW_INSTRUCTIONS},
	{"branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
	{"branch-misses", PERF_COUNT_HW_BRANCH_MISSES},
	{"bus-cycles", PERF_COUNT_HW_BUS_CYCLES},
	{"stalled-cycles-front", PERF_COUNT_HW_STALLED_CYCLES_FRONTEND},
	{"stalled-cycles-back", PERF_COUNT_HW_STALLED_CYCLES_BACKEND},
	{"ref-cycles", PERF_COUNT_HW_REF_CPU_CYCLES},
};

enum PRINT_MODE {
	PRINT_USER,
	PRINT_KERNEL,
	PRINT_OFF_CPU,
};

struct tp_name {
	char category[16];
	char name[48];
};

static void signalHandler(int signum)
{
	done = true;
}

int parse_hardware_flag(char *str)
{
	for (int i = 0; i < ARRAY_LEN(hardware_map); i++)
		if (strcmp(str, hardware_map[i].type_name) == 0)
			return hardware_map[i].type;

	return -1;
}

int print_stack_frame(unsigned long long *frame, unsigned long long sample_num, enum PRINT_MODE mode, void* sym_tb)
{
	char name[128];
	switch (mode) {
	case PRINT_KERNEL:
		printf("[kernel] %llu samples:\n", sample_num);
		for (int i = 0; frame[i] && i < MAX_STACK_DEPTH; i++) {
			ksym_addr_to_sym((struct ksyms*)sym_tb, frame[i], name);
			printf("  %llx %s\n", frame[i], name);
		}
	case PRINT_USER:
		printf("[user] %llu samples:\n", sample_num);
		for (int i = 0; frame[i] && i < MAX_STACK_DEPTH; i++) {
			usym_addr_to_sym((struct usyms*)sym_tb, frame[i], name);
			printf("  %llx %s\n", frame[i], name);
		}
	case PRINT_OFF_CPU:
		printf("[off-cpu] %.5fms:\n", (double)sample_num / 1000000UL);
		for (int i = 0; frame[i] && i < MAX_STACKS; i++) {
			usym_addr_to_sym((struct usyms*)sym_tb, frame[i], name);
			printf("  %llx %s\n", frame[i], name);
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
		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->kstack_id, frame);
		/* kernel stack not available */
		if (cur_key->kstack_id != -EFAULT) {
			if (env.debug && err)
				printf("\n[kernel stack lost]\n");
			else
				print_stack_frame(frame, sample_num, PRINT_KERNEL, ksym_tb);
		}

		err = bpf_map_lookup_elem(stack_map_fd, &cur_key->ustack_id, frame);
		if (env.debug && err)
			printf("\n[user stack lost]\n");
		else
			print_stack_frame(frame, sample_num, PRINT_USER, usym_tb);

		last_key = cur_key;
	} 

	printf("Collected %lld samples\n", sample_num_total);

	free(frame);
	close(stack_map_fd);
	close(sample_fd);
}

void print_stack_off_cpu(struct bpf_map *stack_map, struct bpf_map *off_cpu_data, struct ksyms* _, struct usyms* usym_tb)
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
			print_stack_frame(frame, data, PRINT_OFF_CPU, usym_tb);
		}

		last_key = cur_key;
	} 

	printf("Collected %d off-cpu samples\n", sample_num_total);

	free(frame);
	close(stack_map_fd);
	close(off_cpu_data_fd);
}

int split_event_str() {
	char *token;
	size_t index = 0;
	token = strtok(env.tmp_str, ",");
	while(token != NULL && index < ARRAY_LEN(event_names)) {
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
	int pid_nr_tmp = 0;
	struct stack_ag* stack_ag_p = NULL;

	if (pid_nr == 0)
		pid_nr_tmp = 1;

	stack_ag_p = stack_aggre_off_cpu(stack_map, off_cpu_time, pids, &pid_nr_tmp);

	if (!stack_ag_p) {
		printf("No stack data\n");
		return -1;
	}

	if (pid_nr_tmp)
		pid_nr = pid_nr_tmp;

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
	int pid_nr_tmp = 0;
	struct stack_ag* stack_ag_p = NULL;

	if (pid_nr == 0)
		pid_nr_tmp = 1;

	clock_t start = clock(), diff;

	stack_ag_p = stack_aggre(stack_map, sample, pids, &pid_nr_tmp);

	if (!stack_ag_p) {
		printf("No stack data\n");
		return -1;
	}

	if (pid_nr_tmp)
		pid_nr = pid_nr_tmp;

	/* plot the aggregated stack */
	if(plot(stack_ag_p, env.svg_file_name, pids, pid_nr)) {
		printf("Failed to plot");
		return -1;
	} else {
		printf("\nPlotted to %s\n", env.svg_file_name);
	}

	diff = clock() - start;
	int msec = diff * 1000 / CLOCKS_PER_SEC;
	printf("took %.4fs\n", (float)msec / 1000);

	stack_free(stack_ag_p);

	return 0;
}

void __record_print_help()
{
	char help[] = "\n  Usage:\n\n"
	              "    sberf record [options]\n\n"
	              "  Options:\n\n"
	              "    -p[--pid]: Record running time\n"
	              "    -t[--tracepoint]: Record tracepoints\n"
	              "    -hw[--hardware]: Record hardware events\n\n"
	              "    -s[--syscall]: Record stack traces when a syscall is triggered\n"
	              "    -m[--memory]: Record memory usage\n"
	              "    -op[--off-cpu]: Record OFF-CPU time\n"
	              "    -u[--uprobe]: Record user land symbol\n"
	              "    -h[--help]: Print this help message\n\n"

	              "    -f: Frequency in Hz\n"
	              "    -np: No plotting, print the stacks instead\n"
	              "    -a: Record all processes\n"
	              "    -o: File name for the plot\n"
	              "    -st: Use it with -t/-s/-u to collect stack traces\n"
		      "    -obj: Use it with -u to specify binary/dso path\n"
	              "\n";

	printf("%s", help);
}

int record_print_help(int argc, char **argv, int index)
{
	__record_print_help();
	return 0;
}

void loop_till_interrupt(bool *enabled)
{
	*enabled = true;
	signal(SIGINT, signalHandler);
	for (; !done;) {usleep(10 * 1000);}
	*enabled = false;
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

int record_syscall(int argc, char **argv, int index)
{
	struct event_bpf *skel;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};
	size_t pid_nr;
	struct bpf_link *link = NULL;
	char event_full[64];
	pid_t pids[MAX_PID];
	struct tp_name tp_names[MAX_TP_TRGR_PROG];
	int err = 0, event_num, fd, one = 1, tp_i = 0;
	unsigned long long cnt = 0;
	char tmp[64];

	parse_opts_env(argc, argv, index, event_env, ARRAY_LEN(event_env));

	pid_nr = split_pid(env.pids, pids);
	if (!env.all_p && !pid_nr) {
		__record_print_help();
		return 0;
	}

	event_num = split_event_str();

	if (event_num > 1)
		printf("recording syscalls: ");
	else
		printf("recording syscall: ");

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

	skel->bss->spec_pid = !env.all_p;
	skel->bss->collect_stack = false;

	fd = bpf_map__fd(skel->maps.task_filter);
	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	close(fd);

	err = event_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	for (int i = 0; i < event_num && i < MAX_TP_TRGR_PROG; i++) {
		err = snprintf(event_full, sizeof(event_full), "sys_enter_%s", event_names[i]);
		if (err < 0)
			return err;

		strcpy(tp_names[tp_i].name, event_names[i]);

		link = bpf_program__attach_tracepoint(tp_trigger_prog[tp_i], "syscalls", event_full);
		++tp_i;
		if (link == NULL) {
			printf("Failed to attach syscall %s\n", event_names[i]);
		}
	}

	skel->bss->collect_stack = env.collect_stack;

	loop_till_interrupt(&skel->bss->enabled);

	if (env.no_plot || !env.collect_stack) {
		printf("\n");
		printf("    %-32s    %s\n\n", "syscall", "count");

		fd = bpf_map__fd(skel->maps.event_cnt);
		if (fd < 0) {
			printf("Failed to find fd of event counting map\n");
			goto cleanup;
		}

		for (unsigned int i = 0; i < tp_i && i < MAX_TP_TRGR_PROG; i++) {
			err = bpf_map_lookup_elem(fd, &i, &cnt);
			if (err)
				cnt = 0;

			sprintf(tmp, "%s", tp_names[i].name);
			printf("    %-32s    %llu\n", tmp, cnt);
		}

		printf("\n");
	} else {
		record_plot(skel->maps.stack_map, skel->maps.sample, pids, pid_nr);
	}


cleanup:
	close(fd);
	event_bpf__destroy(skel);
	return err;
}

int record_tracepoint(int argc, char **argv, int index)
{
	struct event_bpf *skel;
	struct bpf_link *link = NULL;
	struct tp_name tp_names[MAX_TP_TRGR_PROG];
	int err = 0, event_num = 0, fd, one = 1, tp_i = 0;
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

	skel->bss->spec_pid = !env.all_p;
	skel->bss->collect_stack = env.collect_stack;

	fd = bpf_map__fd(skel->maps.task_filter);
	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	close(fd);

	for (int i = 0; i < event_num && i < MAX_TP_TRGR_PROG; i++) {
		/* syscalls:sys_enter_open */
		char *tracepoint;
		size_t index = 0;

		/* event_names[i] now is the category(syscalls), tracepoint is sys_enter_open */
		strtok(event_names[i], ":");
		tracepoint = strtok(NULL, ":");

		if (tracepoint == NULL) {
			printf("Illegal event name %s\n", event_names[i]);
			if (event_num == 1)
				goto cleanup;
			else
				continue;
		}

		strcpy(tp_names[tp_i].category, event_names[i]);
		strcpy(tp_names[tp_i].name, tracepoint);

		link = bpf_program__attach_tracepoint(tp_trigger_prog[tp_i], event_names[i], tracepoint);
		++tp_i;
		if (link == NULL) {
			printf("Failed to attach tracepoint %s:%s\n", event_names[i], tracepoint);
		}
	}
	
	err = event_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	loop_till_interrupt(&skel->bss->enabled);

	if (env.no_plot || !env.collect_stack) {
		printf("\n");
		printf("    %-46s    %s\n\n", "event", "count");

		fd = bpf_map__fd(skel->maps.event_cnt);
		if (fd < 0) {
			printf("Failed to find fd of event counting map\n");
			goto cleanup;
		}

		for (unsigned int i = 0; i < tp_i && i < MAX_TP_TRGR_PROG; i++) {
			err = bpf_map_lookup_elem(fd, &i, &cnt);
			if (err)
				cnt = 0;

			sprintf(tmp, "%s:%s", tp_names[i].category, tp_names[i].name);
			printf("    %-46s    %llu\n", tmp, cnt);
		}

		printf("\n");
	} else {
		record_plot(skel->maps.stack_map, skel->maps.sample, pids, pid_nr);
	}

cleanup:
	close(fd);
	event_bpf__destroy(skel);
	return err;
}

int record_pid(int argc, char **argv, int index)
{
	struct record_bpf *skel;
	int err = 0, one = 1, fd;
	int cpu_nr = sysconf(_SC_NPROCESSORS_ONLN);
	struct bpf_link* link;
	size_t pid_nr;
	unsigned long long freq, sample_freq;
	struct ksyms* ksym_tb;
	struct usyms* usym_tb;
	pid_t pids[MAX_PID];
	struct perf_event_attr attr;
	char *comm;

	memset(&attr, 0, sizeof(attr));

	attr.type = PERF_TYPE_SOFTWARE,
	attr.config = PERF_COUNT_SW_CPU_CLOCK,

	parse_opts_env(argc, argv, index, pid_env, ARRAY_LEN(pid_env));

	skel = record_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	pid_nr = split_pid(env.pids, pids);

	printf("Recording commands: ");
	for (int i = 0; i < pid_nr; i++) {
		comm = get_comm(pids[i]);
		printf("%s ", comm);
		free(comm);
	}
	printf("\n");

	/* sberf record $pid is also legal */
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

	close(fd);

	freq = env.freq;
	sample_freq = env.sample_freq; 

	attr.freq = freq;
	attr.sample_freq = sample_freq;

	bpf_map__set_max_entries(skel->maps.stack_map, MAX_ENTRIES);

	err = record_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* record all process */
	if (env.all_p){ 
		for (int i = 0; i < cpu_nr; i++) {
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
		for (int i = 0; i < pid_nr; i++) {
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
	printf("in %lld Hz\n", env.sample_freq);

	loop_till_interrupt(&skel->bss->enabled);

	if (env.no_plot) {
		ksym_tb = ksym_load();
		usym_tb = usym_load(pids, pid_nr);

		if (env.debug && ksym_tb && usym_tb)
			printf("\nSymbols loaded\n");

		print_stack(skel->maps.stack_map, skel->maps.sample, ksym_tb, usym_tb);

		ksym_free(ksym_tb);
		usym_free(usym_tb);
	} else {
		record_plot(skel->maps.stack_map, skel->maps.sample, pids, pid_nr);
	}

cleanup:
	record_bpf__destroy(skel);
	return err;
}

int record_mem(int argc, char **argv, int index)
{
	struct mem_bpf *skel;
	int err = 0;
	size_t pid_nr;
	pid_t pids[MAX_PID];

	printf("sberf record -m[--memory] is under development, coming soon\n");
	exit(0);

	parse_opts_env(argc, argv, index, mem_env, ARRAY_LEN(mem_env));

	skel = mem_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	pid_nr = split_pid(env.pids, pids);
	if (!pid_nr) {
		__record_print_help();
		return 0;
	}
	
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

	loop_till_interrupt(&skel->bss->enabled);

cleanup:
	mem_bpf__destroy(skel);
	return err;
}

int record_off_cpu(int argc, char **argv, int index)
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
	
	skel->bss->spec_pid = !env.all_p;

	if (pid_nr == 0)
		skel->bss->spec_pid = false;

	fd = bpf_map__fd(skel->maps.task_filter);
	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	close(fd);

	err = off_cpu_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Recording OFF-CPU ");
	for (int i = 0; i < pid_nr; i++)
		printf("%d ", pids[i]);
	printf("\n");

	loop_till_interrupt(&skel->bss->enabled);

	if (env.no_plot) {
		usym_tb = usym_load(pids, pid_nr);
		if (usym_tb == NULL) {
			printf("Failed to load off-cpu symbol table\n");
			goto cleanup;
		}

		if (env.debug && usym_tb) {
			printf("\nsymbols loaded\n");
			printf("symbol table len %d\n", usym_tb->length);
		}

		print_stack_off_cpu(skel->maps.stacks, skel->maps.off_cpu_time, NULL, usym_tb);

		usym_free(usym_tb);
	} else {
		record_plot_off_cpu(skel->maps.stacks, skel->maps.off_cpu_time, pids, pid_nr);
	}

cleanup:
	off_cpu_bpf__destroy(skel);
	return err;
}

int record_numa(int argc, char **argv, int index)
{
	return 0;
}

int record_hardware(int argc, char **argv, int index)
{
	/*
	 * For pid-specific hardware events,
	 * sberf now can only specify one
	 * pid at a time.
	 */
	struct event_bpf *skel;
	struct bpf_link* link;
	struct perf_event_attr attr;
	int **fds, fd, event_num, flag, err = 0, k = 0;
	size_t pid_nr;
	pid_t pids[MAX_PID];
	int cpu_nr = sysconf(_SC_NPROCESSORS_ONLN);
	bool default_hw = false;
	__u64 cnt_tmp, cnt;
	int default_tmp[] = {PERF_COUNT_HW_CPU_CYCLES,
			     PERF_COUNT_HW_INSTRUCTIONS,
			     PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
			     PERF_COUNT_HW_BRANCH_MISSES};

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.disabled = 1;

	parse_opts_env(argc, argv, index, hardware_env, ARRAY_LEN(hardware_env));

	pid_nr = split_pid(env.pids, pids);

	event_num = split_event_str();

	if (event_num == 0) {
		default_hw = true;
		event_num = 4;
	}
		
	fds = malloc(sizeof(int *) * event_num);
	for (int i = 0; i < event_num; i++)
		fds[i] = malloc(sizeof(int) * cpu_nr);

	for (int i = 0; i < MAX_HARDWARE && i < event_num; i++) {
		flag = parse_hardware_flag(event_names[i]);
		if (flag != -1) {
			attr.config = flag;
			for (int j = 0; j < cpu_nr; j++) {
				if (pid_nr == 0)
					fd = syscall(__NR_perf_event_open, &attr, -1, j, -1, 0);
				else
					fd = syscall(__NR_perf_event_open, &attr, pids[0], j, -1, 0);
				if (fd < 0) {
					printf("Failed to open perf event for %s\n", event_names[i]);
					goto cleanup;
				}
				
				fds[i][j] = fd;
			}
		}
	}

	if (default_hw) {
		for (int i = 0; i < ARRAY_LEN(default_tmp); i++) {
			attr.config = default_tmp[i];
			for (int j = 0; j < cpu_nr; j++) {
				if (pid_nr == 0)
					fd = syscall(__NR_perf_event_open, &attr, -1, j, -1, 0);
				else
					fd = syscall(__NR_perf_event_open, &attr, pids[0], j, -1, 0);
				if (fd < 0) {
					printf("This machine probably doesn't support hardware events\n");
					goto cleanup;
				}
				
				fds[i][j] = fd;
			}
		}
	}

	for (int i = 0; i < event_num; i++) {
		for (int j = 0; j < cpu_nr; j++) {
			ioctl(fds[i][j], PERF_EVENT_IOC_RESET, 0);
			ioctl(fds[i][j], PERF_EVENT_IOC_ENABLE, 0);
		}
	}

	signal(SIGINT, signalHandler);

	for (; !done;) {usleep(10 * 1000);}

	printf("\n\n");
	printf("  %-20s %-64s\n\n", "hardware-event", "count");

	if (default_hw) {
		__u64 cnt_arr[ARRAY_LEN(default_tmp)];

		for (int i = 0; i < event_num; i++) {
			cnt = 0;
			for (int j = 0; j < cpu_nr; j++) {
				ioctl(fds[i][j], PERF_EVENT_IOC_DISABLE, 0);
				err = read(fds[i][j], &cnt_tmp, sizeof(cnt_tmp));
				if (err)
					return err;
				cnt += cnt_tmp;
			}
			cnt_arr[i] = cnt;
		}

		char br_ms[64];
		sprintf(br_ms, "%llu (%%%.6f)", cnt_arr[3], (double)cnt_arr[3] / (double)cnt_arr[2] * 100);

		printf("  %-20s %-64llu\n", "cycles", cnt_arr[0]);
		printf("  %-20s %-64llu\n", "instructions", cnt_arr[1]);
		printf("  %-20s %-64llu\n", "branches", cnt_arr[2]);
		printf("  %-20s %-64s\n", "branch-misses", br_ms);
	} else {
		for (int i = 0; i < event_num; i++) {
			cnt = 0;
			for (int j = 0; j < cpu_nr; j++) {
				ioctl(fds[i][j], PERF_EVENT_IOC_DISABLE, 0);
				err = read(fds[i][j], &cnt_tmp, sizeof(cnt_tmp));
				if (err)
					return err;
				cnt += cnt_tmp;
			}
			printf("  %-20s %-64llu\n", event_names[i], cnt);
		}
	}

	printf("\n");

cleanup:
	for (int i = 0; i < event_num; i++) {
		for (int j = 0; j < cpu_nr; j++)
			close(fds[i][j]);
		free(fds[i]);
	}
	free(fds);

	return err;
}

int record_uprobe(int argc, char **argv, int index)
{
	struct event_bpf *skel;
	struct bpf_link *link = NULL;
	pid_t pids[MAX_PID];
	size_t pid_nr;
	int fd, one = 1, err = 0, zero = 0;
	unsigned long long cnt;

	parse_opts_env(argc, argv, index, uprobe_env, ARRAY_LEN(uprobe_env));

	printf("Recording symbol %s from path %s\n", env.uprobe_symbol, env.object_path);

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

	pid_nr = split_pid(env.pids, pids);
	if (!pid_nr) {
		printf("Please specify pid for uprobe\n");
		return 0;
	}

	skel->bss->spec_pid = true;
	skel->bss->collect_stack = env.collect_stack;

	fd = bpf_map__fd(skel->maps.task_filter);
	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	close(fd);

	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = env.uprobe_symbol, .retprobe = false);
	link = bpf_program__attach_uprobe_opts(skel->progs.uprobe_trgr, pids[0], env.object_path, 0, &uprobe_opts);
	if (link == NULL) {
		printf("Failed to attach uprobe\n");
		goto cleanup;
	}

	err = event_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	loop_till_interrupt(&skel->bss->enabled);

	if (env.no_plot || !env.collect_stack) {
		printf("\n");
		printf("    %-46s    %s\n\n", "func", "count");

		fd = bpf_map__fd(skel->maps.event_cnt);
		if (fd < 0) {
			printf("Failed to find fd of event counting map\n");
			goto cleanup;
		}

		err = bpf_map_lookup_elem(fd, &zero, &cnt);
		if (err)
			cnt = 0;

		printf("    %-46s    %llu\n", env.uprobe_symbol, cnt);

		printf("\n");
	} else {
		record_plot(skel->maps.stack_map, skel->maps.sample, pids, pid_nr);
	}

cleanup:
	event_bpf__destroy(skel);
	return err;
}

int record_kprobe(int argc, char **argv, int index)
{
	return 0;
}

int record_lock(int argc, char** argv, int index)
{
	struct lock_bpf *skel;
	struct bpf_link *link = NULL;
	pid_t pids[MAX_PID];
	size_t pid_nr;
	int fd, one = 1, err = 0, zero = 0;
	unsigned long long cnt;

	parse_opts_env(argc, argv, index, uprobe_env, ARRAY_LEN(uprobe_env));

	skel = lock_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load record's BPF skeleton\n");
		return 1;
	}

	err = lock_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	pid_nr = split_pid(env.pids, pids);
	if (!pid_nr) {
		printf("Please specify pid for recording lock\n");
		return 0;
	}

	/* has to be true */
	skel->bss->spec_pid = true;

	fd = bpf_map__fd(skel->maps.task_filter);
	for (int i = 0;i < pid_nr;i++)
		bpf_map_update_elem(fd, &pids[i], &one, BPF_ANY);

	close(fd);

	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = LOCK_WAIT, .retprobe = false);
	link = bpf_program__attach_uprobe_opts(skel->progs.enter_wait, pids[0], LIB_PTHREAD, 0, &uprobe_opts);
	if (link == NULL) {
		printf("Failed to attach lock's uprobe\n");
		goto cleanup;
	}

	err = lock_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	loop_till_interrupt(&skel->bss->enabled);

cleanup:
	lock_bpf__destroy(skel);
	return err;

	return 0;
}
