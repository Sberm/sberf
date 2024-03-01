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
#include <stdlib.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "sub_commands.h"
#include "util.h"
#include "record.skel.h"
#include "record.h"


static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	printf("user stack:\n");
	for (int i = 0;i < e->ustack_sz; i++) {
		printf("%016llx\n", e->ustack[i]);
	} 
	printf("\n");
	printf("kernel stack:\n");
	for (int i = 0;i < e->kstack_sz; i++) {
		printf("%016llx\n", e->kstack[i]);
	}
	printf("\n");
}

int cmd_record(int argc, char **argv)
{
	if (argc < 3) {
		char prompt[] = "\n  Usage:\n"
		                "\n    sberf record <PID>\n\n";
		printf("%s", prompt);
		return 0;
	}

	struct perf_buffer *pb = NULL;
	struct record_bpf *skel;
	int err;

	/* Load and verify BPF application */
	skel = record_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Tell eBPF which PID to trace */
	pid_t pid_to_trace = atoi(argv[2]);
	skel->bss->pid_to_trace = pid_to_trace;

	unsigned long long freq = 1;
	unsigned long long sample_freq = 49; 

	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = freq,
		.sample_freq = sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	int cpus = libbpf_num_possible_cpus();
	int fd;

	/* Load & verify BPF programs */
	err = record_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	printf("Recording %llu\n", pid_to_trace);

	// on any cpu
	fd = syscall(__NR_perf_event_open, &attr, pid_to_trace, -1, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) {
		// meaning that cpu is idle
		if (errno == ENODEV) {}
			// do something
		printf("Failed to record pid %d\n", pid_to_trace);
	}
	int a_p_e =  bpf_program__attach_perf_event(skel->progs.profile, fd);
	if (!a_p_e) {
		printf("Failed to attach bpf program\n");
		goto cleanup;
	}

	err = record_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up perf buffer polling */
	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8, handle_event, NULL, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	while (true) {
		err = perf_buffer__poll(pb, 100);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	perf_buffer__free(pb);
	record_bpf__destroy(skel);

	return 0;
}
