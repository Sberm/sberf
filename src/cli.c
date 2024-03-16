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

struct cmd_struct {
	const char* cmd;
	int (*fn)(int, char**);
};

static struct cmd_struct commands[] = {
	{"record", cmd_record},
	// {"stat", cmd_stat},
};

void print_help() {
	char help_message[] = "\n  Usage:\n\n"
                          "    sberf record <PID>\n"
                          "    sberf plot <REC>\n\n";
	printf("%s", help_message);
}

void parse_args(int argc, char** argv)
{
	if (argc < 2) {
		print_help();
		return;
	}

	int parse_flag = 0;
	for (int i = 0;i < ARRAY_LEN(commands); i++) {
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
