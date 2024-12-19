/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef PLOT_H
#define PLOT_H

#include "comm.h"

int plot(struct stack_ag *p, char *file_name, struct comm_pids *comms);
int plot_off_cpu(struct stack_ag *p, char *file_name, struct comm_pids *comms);

#endif
