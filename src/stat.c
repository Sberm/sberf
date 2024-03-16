#include "stat.h"
#include "stat.skel.h"

static void signalHandler(int signum)
{
}

int cmd_stat(int argc, char **argv)
{
	if (argc < 3) {
		char help[] = "\n  Usage:\n"
	                  "\n    sberf stat <event>\n\n";
		printf("%s", help);
		return 0;
	}

	char event[128];
	strcpy(event, argv[3]);

	struct stat_bpf *skel;
	int err;

	skel = stat_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load stat's BPF skeleton\n");
		return 1;
	}

	/* pids to trace */
	pid_t *pids = skel->bss->pids;
	size_t num_of_pids = split(argv[2], pids);

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

	/* consume sigint */
	signal(SIGINT, signalHandler);

	// TODO: parse command
	sleep(100);

cleanup:
	stat_bpf__destroy(skel);

	return 0;
}
