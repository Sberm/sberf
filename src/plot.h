/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef PLOT_H
#define PLOT_H

int plot(struct stack_ag *p, char* name_of_plot, pid_t* pids, int num_of_pids);
int plot_off_cpu(struct stack_ag *p, char* file_name, pid_t* pids, int num_of_pids);

#endif
