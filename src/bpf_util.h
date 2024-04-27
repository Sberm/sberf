#ifndef BPF_UTIL_H
#define BPF_UTIL_H

#define TF 1024

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u8));
	__uint(max_entries, TF);
} task_filter SEC(".maps");

static int inline filter_pid(pid_t pid)
{
	if (!bpf_map_lookup_elem(&task_filter, &pid))
		return 1;
	else
		return 0;
}

static void* bpf_map_lookup_insert(void *map, const void *key, const void *init_val)
{
	void *ret;
	ret = bpf_map_lookup_elem(map, key);
	if (ret) 
		return ret;

	int err = bpf_map_update_elem(map, key, init_val, BPF_NOEXIST);
	if (err)
		return NULL;

	ret = bpf_map_lookup_elem(map, key);
	return ret;
}


#endif
