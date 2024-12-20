/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "comm.h"

#define PROC_COMM_FMT "/proc/%d/comm"

char *comm__find_by_pid(struct comm_pids *comms, pid_t pid)
{
	struct comm_pid comm_pid = {
		.pid = pid,
	};

	struct comm_pid *res;

	/* We assume that this array of commands is sorted */
	res = bsearch(&comm_pid, comms->comm_pid, comms->nr, sizeof(struct comm_pid), comm_compar);
	if (res == NULL)
		return NULL;

	return res->comm;
}

int get_comm(int pid, char *buf, int buf_size)
{
	char path[128];
	ssize_t bytes;
	int fd;

	buf[0] = 0;

	if (snprintf(path, sizeof(path), PROC_COMM_FMT, pid) <= 0) {
		printf("Can't format path to procfs\n");
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("Can't open procfs of %d\n", pid);
		return -1;
	}

	bytes = read(fd, buf, buf_size);
	if(bytes <= 0) {
		printf("Can't read command from %s\n", path);
		return -1;
	}

	/* The comm in proc fs has a trailing newline */
	buf[bytes - 1] = '\0';

	return 0;
}
