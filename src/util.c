/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

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
