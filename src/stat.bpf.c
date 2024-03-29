/*-*- coding:utf-8                                                          -*-│
│vi: set net ft=c ts=4 sts=4 sw=4 fenc=utf-8                                :vi│
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

#include "vmlinux.h"
#include "stat.h"
#include "bpf_util.h"
#include "util.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} stat_cnt SEC(".maps");

SEC("tracepoint")
int stat_tracepoint(void *ctx)
{
	bpf_printk("triggered");

	u64 zero = 0;
	u64* cnt = bpf_map_lookup_insert(&stat_cnt, &zero, &zero);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else {
		bpf_printk("Failed to look up stack sample");
		return -1;
	}
	return 0;
}

SEC("ksyscall")
int stat_ksyscall(void *ctx)
{
	bpf_printk("triggered");
	u64 zero = 0;
	u64* cnt = bpf_map_lookup_insert(&stat_cnt, &zero, &zero);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else {
		bpf_printk("Failed to look up stack sample");
		return -1;
	}
	return 0;
}
