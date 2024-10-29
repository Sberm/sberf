/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef UTIL_H
#define UTIL_H

#define DB printf("[Debug]\n");
#define DS(fmt, args...) printf(fmt, ##args), printf("\n");
#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

/* avoid double evaluation */
#define max(a,b) \
({ __typeof__ (a) _a = (a); \
   __typeof__ (b) _b = (b); \
 _a > _b ? _a : _b; })

#define min(a,b) \
({ __typeof__ (a) _a = (a); \
   __typeof__ (b) _b = (b); \
 _a < _b ? _a : _b; })

struct loading_args {
	char str[64];
	char dot;
};

void *print_loading(void *_args);

#endif
