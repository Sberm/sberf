#ifndef BPF_UTIL_H
#define BPF_UTIL_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

void* bpf_map_lookup_insert(void *map, const void *key, const void *init_val)
{
	void *ret;
	ret = bpf_map_lookup_elem(map, key);
	if (ret) 
		return ret;

	int err = bpf_map_update_elem(map, key, init_val, BPF_NOEXIST);
	if (err) {
		return NULL;
	}

	ret = bpf_map_lookup_elem(map, key);
	return ret;
}


#endif
