#include "cli.h"
#include <stdio.h>

struct cmd_struct {
	const char* cmd;
	int (*fn)(int, const char**);
};

static struct cmd_struct commands[] = {
	{"record", cmd_record},
	{"plot", cmd_plot},
};


