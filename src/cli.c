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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cli.h"
#include "util.h"
#include "sub_commands.h"

static struct cmd_struct commands[] = {
	{"record", cmd_record},
	// {"stat", cmd_stat},
};

void print_help()
{
	char help_message[] = "\n  Usage:\n\n"
                          "    sberf record <PID>\n"
	                      "\n";
	printf("%s", help_message);
}

int (*parse_opts_func(int argc, char** argv, int cur, struct func_struct *opts, int optc))(int argc, char** argv, int cur)
{
	for (int i = cur;i < argc;i++) {
		char* opt = argv[i];
		for (int j = 0;j < optc;j++) {
			if (strcmp(opt, opts[j].opt) == 0) {
				return opts[j].fn;
			}
		}
	}
	return NULL;
}

void parse_opts_env(int argc, char** argv, int cur, struct env_struct *envs, int envc)
{
	for (int i = cur;i < argc;i++) {
		char* opt = argv[i];
		for (int j = 0;j < envc;j++) {
			if (strcmp(opt, envs[j].opt) == 0)
				if (envs[j].type == 4)
					*((int *)envs[j].p) = 1;
			else if (strcmp(opt, envs[j].opt) == 0 && ++i < argc) {
				opt = argv[i];
				switch (envs[j].type) {
				case 0:
					*((int *)envs[j].p) = atoi(opt);
					break;
				case 1:
					strcpy(envs[j].p, opt);
					break;
				case 2:
					*((float *)envs[j].p) = atof(opt);
					break;
				case 3:
					*((double *)envs[j].p) = strtod(opt, NULL);
					break;
				default:
					printf("Illegal type when parsing options\n");
					break;
				}
			}
		}
	}
}

void parse_args(int argc, char** argv)
{
	int parse_flag = 0;

	for (int i = 0;i < argc - 1 && i < ARRAY_LEN(commands); i++) {
		if (strcmp(commands[i].cmd, argv[1]) == 0) {
			parse_flag = 1;
			commands[i].fn(argc, argv);
			break;
		}
	}

	if (!parse_flag) {
		print_help();
		return;
	}
}
