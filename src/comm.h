/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef COMM_H
#define COMM_H

struct comm_pid {
	char comm[16];
	pid_t pid;
};

struct comm_pids {
	struct comm_pid *comm_pid;
	size_t nr;
};

static inline int comm_compar(const void *__a, const void *__b)
{
	const struct comm_pid *a = __a, *b = __b;
	if (a->pid < b->pid)
		return 1;
	else if (a->pid == b->pid)
		return 0;
	else
		return -1;
}

char *comm__find_by_pid(struct comm_pids *comm, pid_t pid);
int get_comm(int pid, char *buf, int buf_size);

#endif
