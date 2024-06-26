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
