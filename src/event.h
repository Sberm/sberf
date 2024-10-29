/*═══════════════════════════════════════════════════════════════════════╗
║                          ©  Howard Chu                                 ║
║                                                                        ║
║ Permission to use, copy, modify, and/or distribute this software for   ║
║ any purpose with or without fee is hereby granted, provided that the   ║
║ above copyright notice and this permission notice appear in all copies ║
╚═══════════════════════════════════════════════════════════════════════*/

#ifndef STAT_H
#define STAT_H

#define TP_TRGR(index)                                               \
SEC("tp")                                                            \
int tp_trgr_##index(void *ctx)                                       \
{                                                                    \
	if (!enabled)                                                \
		return 0;                                            \
	__u64 *cnt, pid_tgid = bpf_get_current_pid_tgid(), zero = 0, \
			       *val;                                 \
	pid_t pid = pid_tgid >> 32;                                  \
	__u32 cnt_key = (index);                                     \
	if (spec_pid && filter_pid(pid))                             \
		return 0;                                            \
	cnt = bpf_map_lookup_insert(&event_cnt, &cnt_key, &zero);    \
	if (cnt)                                                     \
		__sync_fetch_and_add(cnt, 1);                        \
	else                                                         \
		return -1;                                           \
	if (!collect_stack)                                          \
		return 0;                                            \
	struct key_t key;                                            \
	key.pid = pid;                                               \
	key.kstack_id = 0;                                           \
	key.ustack_id = bpf_get_stackid(ctx, &stack_map,             \
			BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);    \
	val = bpf_map_lookup_insert(&sample, &key, &zero);           \
	if (val)                                                     \
		__sync_fetch_and_add(val, 1);                        \
	else                                                         \
		return -1;                                           \
	return 0;                                                    \
}                                                                    \

#endif
