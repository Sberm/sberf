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

#include "comm.h"

#define PROC_COMM_FMT "/proc/%d/comm"

char *get_comm(int pid)
{
	char path[128], buf[128];
	ssize_t bytes;
	int fd;

	buf[0] = 0;

	if (snprintf(path, sizeof(path), PROC_COMM_FMT, pid) <= 0) {
		printf("Can't format path to procfs\n");
		return NULL;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("Can't open procfs of %d\n", pid);
		return NULL;
	}

	bytes = read(fd, buf, sizeof(buf));
	if(bytes <= 0) {
		printf("Can't read command from %s\n", path);
		return NULL;
	}

	/* The comm in proc fs has a trailing newline */
	buf[bytes - 1] = '\0';

	return strdup(buf);
}
