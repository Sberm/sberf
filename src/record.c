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

#include "sub_commands.h"
#include "util.h"
#include "record.skel.h"
#include "record.h"


static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	printf("user stack: %s\n", e->ustack);
}

int cmd_record(int argc, char **argv)
{
	if (argc < 3 || !atoi(argv[2])) {
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
	skel->bss->pid_to_trace = atoi(argv[2]);

	/* Load & verify BPF programs */
	err = record_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
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

	printf("start profiling...\n");

	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
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

// static struct env {
// 	int verbose;
// 	long min_duration_ms;
// } env;
// 
// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
// {
// 	if (level == LIBBPF_DEBUG && !env.verbose)
// 		return 0;
// 	return vfprintf(stderr, format, args);
// }
// 
// static volatile int exiting = 0;
// 
// static void sig_handler(int sig)
// {
// 	exiting = 1;
// }
// 
// static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
// {
// 	const struct event *e = data;
// 	struct tm *tm;
// 	char ts[32];
// 	time_t t;
// 
// 	time(&t);
// 	tm = localtime(&t);
// 	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
// 
// 	if (e->exit_event) {
// 		printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "EXIT", e->comm, e->pid, e->ppid,
// 		       e->exit_code);
// 		if (e->duration_ns)
// 			printf(" (%llums)", e->duration_ns / 1000000);
// 		printf("\n");
// 	} else {
// 		printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid, e->ppid,
// 		       e->filename);
// 	}
// }
// 
// static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
// {
// 	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
// }
// 
// int cmd_record(int argc, char **argv)
// {
// 	if (argc < 3 || !atoi(argv[2])) {
// 		char prompt[] = "\n  Usage:\n"
// 		                "\n    sberf record <PID>\n\n";
// 		printf("%s", prompt);
// 		return 0;
// 	}
// 
// 	struct perf_buffer *pb = NULL;
// 	struct record_bpf *skel;
// 	int err;
// 
// 	/* Set up libbpf errors and debug info callback */
// 	libbpf_set_print(libbpf_print_fn);
// 
// 	/* Cleaner handling of Ctrl-C */
// 	signal(SIGINT, sig_handler);
// 	signal(SIGTERM, sig_handler);
// 
// 	/* Load and verify BPF application */
// 	skel = record_bpf__open();
// 	if (!skel) {
// 		fprintf(stderr, "Failed to open and load BPF skeleton\n");
// 		return 1;
// 	}
// 
// 	/* Tell eBPF which PID to trace */
// 	skel->bss->pid_to_trace = atoi(argv[2]);
// 
// 	/* Parameterize BPF code with minimum duration parameter */
// 	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
// 
// 	/* Load & verify BPF programs */
// 	err = record_bpf__load(skel);
// 	if (err) {
// 		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
// 		goto cleanup;
// 	}
// 
// 	/* Attach tracepoints */
// 	err = record_bpf__attach(skel);
// 	if (err) {
// 		fprintf(stderr, "Failed to attach BPF skeleton\n");
// 		goto cleanup;
// 	}
// 
// 	/* Set up perf buffer polling */
// 	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 8, handle_event, handle_lost_events, NULL, NULL);
// 	if (!pb) {
// 		err = -1;
// 		fprintf(stderr, "Failed to create perf buffer\n");
// 		goto cleanup;
// 	}
// 
// 	/* Process events */
// 	printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID",
// 	       "FILENAME/EXIT CODE");
// 
// 	while (!exiting) {
// 		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
// 		/* Ctrl-C will cause -EINTR */
// 		if (err == -EINTR) {
// 			err = 0;
// 			break;
// 		}
// 		if (err < 0) {
// 			printf("Error polling perf buffer: %d\n", err);
// 			break;
// 		}
// 	}
// 
// cleanup:
// 	/* Clean up */
// 	perf_buffer__free(pb);
// 	record_bpf__destroy(skel);
// 
// 	return err < 0 ? -err : 0;
// }
