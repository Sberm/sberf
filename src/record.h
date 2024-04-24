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

#ifndef RECORD_H
#define RECORD_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 10240
#define MAX_PID 64
#define MAX_STACK_DEPTH 32

struct key_t {
	__u32 pid;
	int user_stack_id;
	int kern_stack_id;
	char comm[TASK_COMM_LEN];
};

int record_syscall(int argc, char** argv, int index);
int record_tracepoint(int argc, char** argv, int index);
int record_pid(int argc, char** argv, int index);
int record_mem(int argc, char** argv, int index);
int record_off_cpu(int argc, char** argv, int index);
int record_print_help(int argc, char** argv, int index);

#endif
