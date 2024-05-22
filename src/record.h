/*-*- coding:utf-8                                                          -*-│
│vi: set ft=c ts=8 sts=8 sw=8 fenc=utf-8                                    :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2024 Howard Chu                                                    │
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
#define MAX_ENTRIES 204800
#define MAX_PID 128
#define MAX_STACK_DEPTH 32

struct key_t {
	__u32 pid;
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
