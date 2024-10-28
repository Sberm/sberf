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

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "util.h"

#define DOTS_NR 5

void *print_loading(void *_args)
{
	struct loading_args *args = _args;
	char *str = args->str;
	char dot = args->dot;

	printf("\n");

	while (true) {
		printf("\33[%ldD", strlen(str) + DOTS_NR);
		printf("\33[0K");
		printf("%s", str);
		fflush(stdout);

		for (int j = 0; j < DOTS_NR; j++) {
			usleep(4 * 100000); // 400ms
			printf("%c", dot);
			fflush(stdout);
		}
	}
}
