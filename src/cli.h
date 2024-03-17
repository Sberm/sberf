/*-*- coding:utf-8                                                          -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
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
#ifndef CLI_H
#define CLI_H

struct cmd_struct {
	const char* cmd;
	int (*fn)(int, char**);
};

struct func_struct {
	char opt[4];
	int (*fn)(int, char**, int);
};

struct env_struct {
	char opt[4];
	char type; // 0 -> int, 1 -> str, 2 -> float, 3 -> double, 4 -> itself as a value(.eg -a)
	void *p;
};

void parse_args(int argc, char** argv);
int (*parse_opts_func(int argc, char** argv, int cur, struct func_struct *opts, int optc))(int argc, char** argv, int cur);
void parse_opts_env(int argc, char** argv, int cur, struct env_struct *envs, int envc);

#endif
