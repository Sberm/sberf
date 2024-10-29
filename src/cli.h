/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef CLI_H
#define CLI_H

enum ENV_MODE {
	INT, STR, FLOAT, DOUBLE, MGL
};

struct cmd_struct {
	const char* cmd;
	int (*fn)(int, char**);
};

struct func_struct {
	char opt[16];
	int (*fn)(int, char**, int);
};

struct env_struct {
	char opt[16];
	enum ENV_MODE type;
	void *p;
};

void parse_args(int argc, char** argv);
int (*parse_opts_func(int argc, char** argv, int cur, struct func_struct *opts, int optc))(int argc, char** argv, int cur);
void parse_opts_env(int argc, char** argv, int cur, struct env_struct *envs, int envc);

#endif
