/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef RECORD_H
#define RECORD_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 204800
#define MAX_PID 128
#define MAX_STACK_DEPTH 32

struct key_t {
	pid_t pid;
	int ustack_id;
	int kstack_id;
};

int record_syscall(int argc, char** argv, int index);
int record_tracepoint(int argc, char** argv, int index);
int record_pid(int argc, char** argv, int index);
int record_mem(int argc, char** argv, int index);
int record_off_cpu(int argc, char** argv, int index);
int record_print_help(int argc, char** argv, int index);
int record_numa(int argc, char** argv, int index);
int record_hardware(int argc, char** argv, int index);
int record_uprobe(int argc, char** argv, int index);
int record_kprobe(int argc, char** argv, int index);
int record_lock(int argc, char** argv, int index);

#endif
